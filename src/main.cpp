#include <QApplication>
#include <QMenu>
#include <QAction>
#include <QTimer>
#include <QDateTime>
#include <atomic>
#include <KLocalizedString>
#include <KMessageBox>
#include <KStatusNotifierItem>
#include "ui/SecurePasswordDialog.h"
#include <QInputDialog>
#include <QTemporaryDir>
#include <QProcess>
#include <QIcon>
#include <QFile>
#include <QTextStream>
#include <QStandardPaths>
#include <QLockFile>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusConnectionInterface>
#include <QFileSystemWatcher>
#include <QElapsedTimer>
#include <QThread>
#include <QDir>
#include <QFileInfo>
#include <QFileDevice>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QRegularExpression>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <cstring>
 

namespace {

void logEvent(const QString &message);
static inline bool debugEnabled() {
    static const bool enabled = qEnvironmentVariableIsSet("SECRETS_LOG_DEBUG");
    return enabled;
}
static inline void debugLog(const QString &message) {
    if (debugEnabled()) logEvent(message);
}

static QString lockoutStatePath();

struct LockoutState {
    qint64 bannedUntilMs = 0; 
    int failureCount = 0;      
    bool permanent = false;    
};

static LockoutState readLockoutState() {
    LockoutState s;
    QFile f(lockoutStatePath());
    if (!f.open(QIODevice::ReadOnly)) return s;
    const auto doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject()) return s;
    const auto o = doc.object();
    s.bannedUntilMs = static_cast<qint64>(o.value(QStringLiteral("banned_until_ms")).toDouble(0));
    s.failureCount = o.value(QStringLiteral("failure_count")).toInt(0);
    s.permanent = o.value(QStringLiteral("permanent")).toBool(false);
    return s;
}

static void writeLockoutState(const LockoutState &s) {
    QJsonObject o;
    o.insert(QStringLiteral("banned_until_ms"), static_cast<double>(s.bannedUntilMs));
    o.insert(QStringLiteral("failure_count"), s.failureCount);
    o.insert(QStringLiteral("permanent"), s.permanent);
    QSaveFile sf(lockoutStatePath());
    if (!sf.open(QIODevice::WriteOnly)) return;
    QJsonDocument doc(o);
    sf.write(doc.toJson(QJsonDocument::Compact));
    sf.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    sf.commit();
}

static qint64 computeBackoffMs(int failures) {
    if (failures >= 15) return -1;           
    if (failures >= 12) return 4LL * 60 * 60 * 1000; 
    if (failures >= 9)  return 30LL * 60 * 1000;     
    if (failures >= 6)  return 5LL * 60 * 1000;      
    if (failures >= 3)  return 60LL * 1000;          
    return 0;
}

static bool checkLockout(QString *msgOut = nullptr) {
    LockoutState s = readLockoutState();
    if (s.permanent) { if (msgOut) *msgOut = QObject::tr("Too many failed attempts. Access permanently disabled."); return true; }
    const qint64 now = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
    if (s.bannedUntilMs > now) {
        const qint64 ms = s.bannedUntilMs - now; qint64 ssec = ms / 1000; qint64 m = ssec / 60; qint64 sec = ssec % 60;
        if (msgOut) *msgOut = QObject::tr("Too many failed attempts. Try again in %1:%2").arg(QString::number(m), QString::number(sec).rightJustified(2, '0'));
        return true;
    }
    return false;
}

static void recordFailure() {
    LockoutState s = readLockoutState();
    s.failureCount += 1;
    const qint64 backoff = computeBackoffMs(s.failureCount);
    if (backoff < 0) {
        s.permanent = true;
        writeLockoutState(s);
        logEvent(QStringLiteral("rate_limit_permanent"));
        return;
    }
    if (backoff > 0) {
        const qint64 now = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
        const qint64 until = now + backoff;
        if (until > s.bannedUntilMs) s.bannedUntilMs = until;
    }
    writeLockoutState(s);
}

static void clearFailuresOnSuccess() {
    LockoutState s = readLockoutState();
    if (s.failureCount == 0 && s.bannedUntilMs == 0 && !s.permanent) return;
    s.failureCount = 0;
    s.bannedUntilMs = 0;
    writeLockoutState(s);
}

static std::atomic_bool gDialogOpen{false};
class ScopedDialogLock {
public:
    explicit ScopedDialogLock(QAction* a1 = nullptr, QAction* a2 = nullptr)
        : a1_(a1), a2_(a2) {
        bool expected = false;
        acquired_ = gDialogOpen.compare_exchange_strong(expected, true, std::memory_order_acq_rel);
        if (acquired_) {
            if (a1_) a1_->setEnabled(false);
            if (a2_) a2_->setEnabled(false);
        }
    }
    ~ScopedDialogLock() {
        if (!acquired_) return;
        if (a1_) a1_->setEnabled(true);
        if (a2_) a2_->setEnabled(true);
        gDialogOpen.store(false, std::memory_order_release);
    }
    bool ok() const { return acquired_; }
private:
    QAction* a1_{nullptr};
    QAction* a2_{nullptr};
    bool acquired_{false};
};

static bool ensurePrivateDir(const QString &path);

QString secretsDirPath() { return QDir::homePath() + "/Secrets"; }
QString encryptedDirPath() { return QDir::homePath() + "/.secrets-encrypted"; }
QString configFilePath() { return encryptedDirPath() + "/.secrets-config"; }

QString stateDirPath() {
    QString dir = QDir::homePath() + "/.local/state";
    ensurePrivateDir(dir);
    return dir;
}

QString logFilePath() { return stateDirPath() + "/secrets-actions.log"; }

static QString lockoutStatePath() { return stateDirPath() + "/secrets-lockout.json"; }

QString pinnedHashFilePath() {
    QString dir = QDir::homePath() + "/.local/share/secrets-actions";
    ensurePrivateDir(dir);
    return dir + "/pinned.json";
}

static bool ensurePrivateDir(const QString &path) {
    const QByteArray encoded = QFile::encodeName(path);
    struct stat st{};
    if (::lstat(encoded.constData(), &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            if (::unlink(encoded.constData()) != 0) {
                return false;
            }
        } else if (!S_ISDIR(st.st_mode)) {
            return false;
        } else {
            if (st.st_uid != getuid()) {
                return false;
            }
            if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
                if (::chmod(encoded.constData(), S_IRWXU) != 0) {
                    return false;
                }
            }
            return true;
        }
    }

    QDir dir;
    if (!dir.mkpath(path)) {
        return false;
    }
    if (::chmod(encoded.constData(), S_IRWXU) != 0) {
        return false;
    }
    if (::lstat(encoded.constData(), &st) != 0) {
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        return false;
    }
    if (st.st_uid != getuid()) {
        return false;
    }
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return false;
    }
    return true;
}

QString runtimeDirPath() {
    static QString cachedRuntimePath;
    if (!cachedRuntimePath.isEmpty()) {
        return cachedRuntimePath;
    }
    const QString xdg = qEnvironmentVariable("XDG_RUNTIME_DIR");
    if (!xdg.isEmpty()) {
        QFileInfo fi(xdg);
        const QFile::Permissions req = QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner;
        if (fi.exists() && fi.isDir() && fi.ownerId() == (uint)getuid()) {
            QFile::Permissions p = fi.permissions();
            if ((p & req) == req && !(p & (QFile::ReadGroup | QFile::WriteGroup | QFile::ExeGroup | QFile::ReadOther | QFile::WriteOther | QFile::ExeOther))) {
                cachedRuntimePath = xdg;
                return cachedRuntimePath;
            }
        }
    }
    const QString fallback = QStringLiteral("/tmp/secrets-%1").arg(getuid());
    if (ensurePrivateDir(fallback)) {
        cachedRuntimePath = fallback;
        return cachedRuntimePath;
    }
    QTemporaryDir tmp(QStringLiteral("/tmp/secrets-fallback-XXXXXX"));
    tmp.setAutoRemove(false);
    cachedRuntimePath = tmp.path();
    ensurePrivateDir(cachedRuntimePath);
    return cachedRuntimePath;
}

static bool isRootHostUidMapped() {
    QFile f(QStringLiteral("/proc/self/uid_map"));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return true;
    }
    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty()) continue;
        const QStringList parts = line.split(QRegularExpression("\\s+"));
        if (parts.size() >= 3) {
            bool ok1=false, ok2=false, ok3=false;
            quint64 inside = parts.at(0).toULongLong(&ok1);
            quint64 outside = parts.at(1).toULongLong(&ok2);
            quint64 length = parts.at(2).toULongLong(&ok3);
            Q_UNUSED(inside);
            if (ok1 && ok2 && ok3) {
                if (outside == 0 && length > 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

static bool isRootOwnedConsideringUserNS(uid_t uid) {
    if (uid == 0) return true;
    const uid_t OVERFLOW = 65534;
    if (uid == OVERFLOW && !isRootHostUidMapped()) return true;
    return false;
}

static int openNoFollowDirFd(const QString &path, QString *errOut = nullptr) {
    const QByteArray encoded = QFile::encodeName(path);
    const int fd = ::open(encoded.constData(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errOut) {
            *errOut = QStringLiteral("Cannot open directory (O_NOFOLLOW): %1 (%2)")
                .arg(path, QString::fromUtf8(strerror(errno)));
        }
        return -1;
    }
    return fd;
}

static bool dirFdIsSecureOwned700(int fd, QString *errOut = nullptr) {
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        if (errOut) {
            *errOut = QStringLiteral("fstat failed: %1").arg(QString::fromUtf8(strerror(errno)));
        }
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        if (errOut) {
            *errOut = QStringLiteral("Not a directory");
        }
        return false;
    }
    if (st.st_uid != getuid()) {
        if (errOut) {
            *errOut = QStringLiteral("Directory not owned by current user (uid=%1, expected=%2)")
                .arg(st.st_uid).arg(getuid());
        }
        return false;
    }
    if ((st.st_mode & 07777) != 0700) {
        if (errOut) {
            *errOut = QStringLiteral("Directory permissions not 0700 (actual=%1)")
                .arg(QString::number(st.st_mode & 07777, 8));
        }
        return false;
    }
    return true;
}

static bool dirFdIsEmpty(int fd, QString *errOut = nullptr) {
    const int newfd = ::dup(fd);
    if (newfd < 0) {
        if (errOut) {
            *errOut = QStringLiteral("dup failed: %1").arg(QString::fromUtf8(strerror(errno)));
        }
        return false;
    }
    DIR *dir = ::fdopendir(newfd);
    if (!dir) {
        ::close(newfd);
        if (errOut) {
            *errOut = QStringLiteral("fdopendir failed: %1").arg(QString::fromUtf8(strerror(errno)));
        }
        return false;
    }
    bool empty = true;
    struct dirent *ent;
    while ((ent = ::readdir(dir)) != nullptr) {
        const char *name = ent->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        empty = false;
        break;
    }
    ::closedir(dir);
    if (!empty && errOut) {
        *errOut = QStringLiteral("Directory is not empty");
    }
    return empty;
}

static bool isPrivateFile0600OwnedByUser(const QString &path, QString *errOut = nullptr) {
    const QByteArray encoded = QFile::encodeName(path);
    struct stat st{};
    if (::lstat(encoded.constData(), &st) != 0) {
        if (errOut) {
            *errOut = QStringLiteral("lstat failed: %1").arg(QString::fromUtf8(strerror(errno)));
        }
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        if (errOut) {
            *errOut = QStringLiteral("File is a symlink");
        }
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        if (errOut) {
            *errOut = QStringLiteral("Not a regular file");
        }
        return false;
    }
    if (st.st_uid != getuid()) {
        if (errOut) {
            *errOut = QStringLiteral("File not owned by current user (uid=%1, expected=%2)")
                .arg(st.st_uid).arg(getuid());
        }
        return false;
    }
    if ((st.st_mode & 0777u) != 0600u) {
        if (errOut) {
            *errOut = QStringLiteral("File permissions not 0600 (actual=%1)")
                .arg(QString::number(st.st_mode & 0777u, 8));
        }
        return false;
    }
    return true;
}

static QElapsedTimer g_mono;
static qint64 g_deadlineMs = 0;
static void setAutolockDeadlineSec(int seconds) {
    if (!g_mono.isValid()) g_mono.start();
    g_deadlineMs = (qint64)g_mono.elapsed() + (qint64)seconds * 1000;
}
static void clearAutolockDeadline() { g_deadlineMs = 0; }
static qint64 remainingAutolockMs() {
    if (!g_mono.isValid() || g_deadlineMs <= 0) return -1;
    return g_deadlineMs - (qint64)g_mono.elapsed();
}

static inline void secure_bzero(void *p, size_t n) {
    if (!p || n == 0) return;
#if defined(__GLIBC__)
    explicit_bzero(p, n);
#else
    volatile unsigned char *vp = reinterpret_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
#endif
}

static QString decodeOctalEscapes(const QString &in) {
    QString out; out.reserve(in.size());
    for (int i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 3 < in.size()) {
            if (in[i+1].isDigit() && in[i+2].isDigit() && in[i+3].isDigit()) {
                int v = (in[i+1].unicode() - '0') * 64 + (in[i+2].unicode() - '0') * 8 + (in[i+3].unicode() - '0');
                out.append(QChar(v)); i += 3; continue;
            }
        }
        out.append(in[i]);
    }
    return out;
}

static QString normalizeForCompare(const QString &p) {
    QString n = QFileInfo(p).absoluteFilePath(); if (n.endsWith('/')) n.chop(1); return n;
}

bool isMountpointPath(const QString &path) {
    const QString needle = normalizeForCompare(path);
    {
        QFile f("/proc/self/mounts");
        if (f.open(QIODevice::ReadOnly)) {
            QByteArray data = f.readAll();
            QString content = QString::fromLocal8Bit(data);
            QStringList lines = content.split('\n', Qt::SkipEmptyParts);
            for (const QString &line : lines) {
                const QStringList parts = line.split(' ');
                if (parts.size() >= 2) {
                    QString mp = normalizeForCompare(parts.at(1));
                    mp.replace("\\040", " ");
                    if (mp == needle) {
                        return true;
                    }
                }
            }
        }
    }
    {
        QFile f("/proc/self/mountinfo");
        if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&f);
            while (!in.atEnd()) {
                const QString line = in.readLine();
                const QStringList parts = line.split(' ');
                if (parts.size() >= 5) {
                    const QString mp = normalizeForCompare(decodeOctalEscapes(parts.at(4)));
                    if (mp == needle) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

bool ensureDirPath(const QString &path) {
    QFileInfo fi(path);
    if (fi.isSymLink()) return false;
    QDir d(path);
    if (!d.exists()) {
        if (!d.mkpath(".")) return false;
    }
    QFile f(path);
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    return true;
}

QProcessEnvironment safeEnvVars() {
    QProcessEnvironment env;
    env.insert("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin");
    env.insert("LANG", "C");
    env.insert("LC_ALL", "C");
    env.insert("HOME", QDir::homePath());
    const QString xdg = qEnvironmentVariable("XDG_RUNTIME_DIR");
    if (!xdg.isEmpty()) env.insert("XDG_RUNTIME_DIR", xdg);
    const QString tmp = qEnvironmentVariable("TMPDIR");
    if (!tmp.isEmpty()) env.insert("TMPDIR", tmp);
    debugLog(QStringLiteral("env_debug: HOME=") + env.value("HOME") + " XDG=" + env.value("XDG_RUNTIME_DIR"));
    static const char *danger[] = {"LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT","LD_ASSUME_KERNEL","GCONV_PATH","HOSTALIASES","PYTHONPATH","RUBYLIB","NODE_PATH","PERL5LIB","DYLD_INSERT_LIBRARIES"};
    for (const char *k : danger) env.remove(QString::fromLatin1(k));
    return env;
}

QProcessEnvironment safeGuiEnvVars() {
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    static const char *danger[] = {"LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT","LD_ASSUME_KERNEL","GCONV_PATH","HOSTALIASES","PYTHONPATH","RUBYLIB","NODE_PATH","PERL5LIB","DYLD_INSERT_LIBRARIES","QT_PLUGIN_PATH","QT_QPA_PLATFORMTHEME"};
    for (const char *k : danger) env.remove(QString::fromLatin1(k));
    return env;
}

QString findFusermountBinary() { return QStringLiteral("/usr/bin/fusermount3"); }
QString findGocryptfsBinary() { return QStringLiteral("/usr/bin/gocryptfs"); }

bool isExecutableTrustedDetailed(const QString &path, QString *reasonOut) {
    QFileInfo fi(path);
    if (!fi.exists()) { if (reasonOut) *reasonOut = QStringLiteral("not found"); return false; }
    if (!fi.isExecutable()) { if (reasonOut) *reasonOut = QStringLiteral("not executable"); return false; }
    if (fi.isSymLink()) { if (reasonOut) *reasonOut = QStringLiteral("symlink not allowed"); return false; }
    const QString real = fi.canonicalFilePath();
    if (real.isEmpty()) { if (reasonOut) *reasonOut = QStringLiteral("canonicalize failed"); return false; }
    if (real != path) { if (reasonOut) *reasonOut = QStringLiteral("path mismatch"); return false; }
    if (!(real.startsWith("/usr/") || real.startsWith("/bin/") || real.startsWith("/sbin/") || real.startsWith("/usr/local/"))) {
        if (reasonOut) *reasonOut = QStringLiteral("outside trusted prefix");
        return false;
    }
    QByteArray rba = real.toUtf8();
    int fd = ::open(rba.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { if (reasonOut) *reasonOut = QStringLiteral("open failed"); return false; }
    struct stat st{};
    const bool ok = (::fstat(fd, &st) == 0);
    ::close(fd);
    if (!ok) { if (reasonOut) *reasonOut = QStringLiteral("stat failed"); return false; }
    if (!S_ISREG(st.st_mode)) { if (reasonOut) *reasonOut = QStringLiteral("not a regular file"); return false; }
    if (!isRootOwnedConsideringUserNS(st.st_uid)) { if (reasonOut) *reasonOut = QStringLiteral("not root-owned"); return false; }
    if ((st.st_mode & S_IWGRP) || (st.st_mode & S_IWOTH)) { if (reasonOut) *reasonOut = QStringLiteral("world-writable"); return false; }
    return true;
}

bool isExecutableTrusted(const QString &path) {
    return isExecutableTrustedDetailed(path, nullptr);
}

int runWithInput(const QString &program, const QStringList &args, const QByteArray &input, QString *stderrOut) {
    QProcess p;
    p.setProgram(program);
    p.setArguments(args);
    p.setProcessEnvironment(safeEnvVars());
    p.setProcessChannelMode(QProcess::SeparateChannels);
    p.start();
    if (!p.waitForStarted(5000)) {
        return -1;
    }
    p.write(input);
    p.closeWriteChannel();
    if (!p.waitForFinished(30000)) {
        p.kill();
        p.waitForFinished(2000);
        if (stderrOut) *stderrOut = QStringLiteral("timeout");
        return -2;
    }
    if (p.exitStatus() != QProcess::NormalExit) {
        if (stderrOut) *stderrOut = QStringLiteral("crash");
        return -3;
    }
    if (stderrOut) {
        QByteArray err = p.readAllStandardError();
        QByteArray out = p.readAllStandardOutput();
        QByteArray combined = err;
        if (!out.isEmpty()) {
            if (!combined.isEmpty()) combined += "\n";
            combined += out;
        }
        *stderrOut = QString::fromUtf8(combined);
    }
    return p.exitCode();
}

int runQuiet(const QString &program, const QStringList &args, QString *stderrOut) {
    QProcess p;
    p.setProgram(program);
    p.setArguments(args);
    p.setProcessEnvironment(safeEnvVars());
    p.setProcessChannelMode(QProcess::SeparateChannels);
    p.start();
    if (!p.waitForStarted(5000)) {
        return -1;
    }
    if (!p.waitForFinished(30000)) {
        p.kill();
        p.waitForFinished(2000);
        if (stderrOut) *stderrOut = QStringLiteral("timeout");
        return -2;
    }
    if (p.exitStatus() != QProcess::NormalExit) {
        if (stderrOut) *stderrOut = QStringLiteral("crash");
        return -3;
    }
    if (stderrOut) {
        *stderrOut = QString::fromUtf8(p.readAllStandardError());
    }
    return p.exitCode();
}

int readAutolockTimeoutSec() {
    QFile f(configFilePath()); if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return 300;
    QTextStream in(&f); QRegularExpression re("^AUTOLOCK_TIMEOUT=([0-9]{1,10})$");
    while (!in.atEnd()) {
        const QString line = in.readLine();
        if (line.size()>4096) continue;
        auto m = re.match(line);
        if (m.hasMatch()) { int v = m.captured(1).toInt(); if (v < 60) v = 60; if (v > 7200) v = 7200; return v; }
    }
    return 300;
}

bool writeAutolockTimeoutSec(int seconds) {
    if (seconds < 60 || seconds > 7200) {
        return false;
    }
    if (!ensureDirPath(encryptedDirPath())) return false;
    QFile rf(configFilePath());
    QString content;
    if (rf.exists()) {
        if (!rf.open(QIODevice::ReadOnly | QIODevice::Text)) return false;
        content = QString::fromUtf8(rf.readAll());
        rf.close();
    }
    QStringList lines = content.split('\n');
    bool found = false;
    for (QString &l : lines) {
        if (l.startsWith("AUTOLOCK_TIMEOUT=")) {
            l = QStringLiteral("AUTOLOCK_TIMEOUT=") + QString::number(seconds);
            found = true;
        }
    }
    if (!found) lines << QStringLiteral("AUTOLOCK_TIMEOUT=") + QString::number(seconds);
    QSaveFile sf(configFilePath());
    if (!sf.open(QIODevice::WriteOnly | QIODevice::Text)) return false;
    {
        QTextStream out(&sf);
        for (int i=0;i<lines.size();++i) {
            if (i==lines.size()-1 && lines[i].isEmpty()) continue;
            out << lines[i] << '\n';
        }
    }
    sf.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return sf.commit();
}

bool verifyPinnedBinary(const QString &key, const QString &path, QString *reasonOut = nullptr) {
    const QString pinPath = pinnedHashFilePath();
    QString secErr;
    if (!isPrivateFile0600OwnedByUser(pinPath, &secErr)) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("pinned.json security check failed: %1").arg(secErr);
        }
        logEvent(QStringLiteral("verifyPinnedBinary_security_fail: ") + secErr);
        return false;
    }
    const QByteArray pinEncoded = QFile::encodeName(pinPath);
    const int pinFd = ::open(pinEncoded.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (pinFd < 0) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("cannot open pinned.json (O_NOFOLLOW): %1")
                .arg(QString::fromUtf8(strerror(errno)));
        }
        return false;
    }
    QByteArray jsonData;
    {
        char buf[1 << 14];
        for (;;) {
            const ssize_t n = ::read(pinFd, buf, sizeof buf);
            if (n < 0) {
                if (errno == EINTR) continue;
                ::close(pinFd);
                if (reasonOut) {
                    *reasonOut = QStringLiteral("read pinned.json failed: %1")
                        .arg(QString::fromUtf8(strerror(errno)));
                }
                return false;
            }
            if (n == 0) break;
            jsonData.append(buf, static_cast<int>(n));
            if (jsonData.size() > (1 << 20)) {
                ::close(pinFd);
                if (reasonOut) {
                    *reasonOut = QStringLiteral("pinned.json too large");
                }
                return false;
            }
        }
    }
    ::close(pinFd);
    auto doc = QJsonDocument::fromJson(jsonData);
    if (!doc.isObject()) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("pinned.json invalid JSON");
        }
        return false;
    }
    auto obj = doc.object();
    const int schema = obj.value(QStringLiteral("schema")).toInt(0);
    if (schema != 1) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("pinned.json schema mismatch (expected 1, got %1)").arg(schema);
        }
        logEvent(QStringLiteral("verifyPinnedBinary_schema_fail: expected=1 actual=") + QString::number(schema));
        return false;
    }
    if (!obj.contains(key)) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("no entry for %1").arg(key);
        }
        return false;
    }
    const QString expected = obj.value(key).toString().trimmed().toLower();
    if (expected.size() != 64) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("hash invalid length");
        }
        return false;
    }
    QByteArray pba = path.toUtf8();
    int fd = ::open(pba.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("open binary failed");
        }
        return false;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        ::close(fd);
        if (reasonOut) {
            *reasonOut = QStringLiteral("stat binary failed");
        }
        return false;
    }
    if (!isRootOwnedConsideringUserNS(st.st_uid) || (st.st_mode & S_IWGRP) || (st.st_mode & S_IWOTH)) {
        ::close(fd);
        if (reasonOut) {
            *reasonOut = QStringLiteral("untrusted owner/perms");
        }
        return false;
    }
    QCryptographicHash h(QCryptographicHash::Sha256);
    char buf[1 << 16];
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            if (reasonOut) {
                *reasonOut = QStringLiteral("read binary failed");
            }
            return false;
        }
        if (n == 0) break;
        h.addData(QByteArrayView(buf, n));
    }
    ::close(fd);
    const QString actual = QString::fromLatin1(h.result().toHex()).toLower();
    if (actual.size() != expected.size()) {
        if (reasonOut) {
            *reasonOut = QStringLiteral("hash mismatch");
        }
        return false;
    }
    int diff = 0;
    for (int i = 0; i < expected.size(); ++i) {
        diff |= (expected[i].unicode() ^ actual[i].unicode());
    }
    bool ok = (diff == 0);
    if (!ok && reasonOut) {
        *reasonOut = QStringLiteral("hash mismatch");
    }
    return ok;
}

static QString octPerms(mode_t m) {
    return QString("%1").arg(static_cast<unsigned>(m & 07777u), 4, 8, QLatin1Char('0'));
}

static QString sha256OfFile(const QString &path) {
    QByteArray pba = QFile::encodeName(path);
    int fd = ::open(pba.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return QString();
    QCryptographicHash h(QCryptographicHash::Sha256);
    char buf[1<<16];
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) { if (errno == EINTR) continue; ::close(fd); return QString(); }
        if (n == 0) break;
        h.addData(QByteArrayView(buf, n));
    }
    ::close(fd);
    return QString::fromLatin1(h.result().toHex()).toLower();
}

static void logTrustDiagnosticsFor(const QString &name, const QString &path, const QString &key) {
    QStringList parts;
    parts << QStringLiteral("trust_diag");
    parts << QStringLiteral("name=%1").arg(name);
    parts << QStringLiteral("path=%1").arg(path);
    const QString canon = QFileInfo(path).canonicalFilePath();
    parts << QStringLiteral("canon=%1").arg(canon.isEmpty() ? QStringLiteral("-") : canon);

    QByteArray pba = QFile::encodeName(path);
    struct stat lst{};
    if (::lstat(pba.constData(), &lst) == 0) {
        parts << QStringLiteral("lstat.uid=%1").arg(lst.st_uid);
        parts << QStringLiteral("lstat.gid=%1").arg(lst.st_gid);
        parts << QStringLiteral("lstat.mode=0%1").arg(octPerms(lst.st_mode));
        parts << QStringLiteral("lstat.islnk=%1").arg(S_ISLNK(lst.st_mode) ? QStringLiteral("1") : QStringLiteral("0"));
    } else {
        parts << QStringLiteral("lstat.err=%1").arg(QString::fromUtf8(strerror(errno)));
    }

    struct stat fst{};
    int fd = ::open(pba.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        if (::fstat(fd, &fst) == 0) {
            parts << QStringLiteral("fstat.uid=%1").arg(fst.st_uid);
            parts << QStringLiteral("fstat.gid=%1").arg(fst.st_gid);
            parts << QStringLiteral("fstat.mode=0%1").arg(octPerms(fst.st_mode));
            parts << QStringLiteral("fstat.isreg=%1").arg(S_ISREG(fst.st_mode) ? QStringLiteral("1") : QStringLiteral("0"));
        } else {
            parts << QStringLiteral("fstat.err=%1").arg(QString::fromUtf8(strerror(errno)));
        }
        ::close(fd);
    } else {
        parts << QStringLiteral("open.err=%1").arg(QString::fromUtf8(strerror(errno)));
    }

    QString reasonT, reasonP;
    const bool trusted = isExecutableTrustedDetailed(path, &reasonT);
    const bool pinned = verifyPinnedBinary(key, path, &reasonP);
    parts << QStringLiteral("trusted=%1").arg(trusted ? QStringLiteral("1") : QStringLiteral("0"));
    parts << QStringLiteral("rT=%1").arg(reasonT.isEmpty() ? QStringLiteral("-") : reasonT);
    parts << QStringLiteral("pinned=%1").arg(pinned ? QStringLiteral("1") : QStringLiteral("0"));
    parts << QStringLiteral("rP=%1").arg(reasonP.isEmpty() ? QStringLiteral("-") : reasonP);

    const QString actual = sha256OfFile(path);
    parts << QStringLiteral("sha256.actual=%1").arg(actual.isEmpty() ? QStringLiteral("-") : actual);

    debugLog(parts.join(' '));
}

bool tryUnmountPath(const QString &path, QString *errOut) {
    QString err;
    const QString fbin = findFusermountBinary();
    QString r1; QString r2;
    const bool trusted = isExecutableTrustedDetailed(fbin, &r1);
    const bool pinned = verifyPinnedBinary("fusermount3", fbin, &r2);
    if (!trusted || !pinned) {
        if (errOut) *errOut = QStringLiteral("untrusted fusermount3 (%1)").arg(!trusted ? r1 : r2);
        return false;
    }
    int rc = runQuiet(fbin, {"-u", path}, &err);
    if (rc == 0) {
        if (errOut) *errOut = QString();
        return true;
    }
    rc = runQuiet(fbin, {"-uz", path}, &err);
    if (rc == 0) {
        if (errOut) *errOut = QString();
        return true;
    }
    if (errOut) {
        *errOut = err;
    }
    return false;
}

bool isDirPermissionsSecure(const QString &path) {
    const QByteArray encoded = QFile::encodeName(path);
    struct stat st{};
    if (::lstat(encoded.constData(), &st) != 0) {
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        return false;
    }
    if (st.st_uid != getuid()) {
        return false;
    }
    if ((st.st_mode & 07777) != 0700) {
        return false;
    }
    return true;
}

static void rotateLogsIfNeeded() {
    const QString log = logFilePath(); QFileInfo fi(log); const qint64 maxSize = 1024*1024;
    if (fi.exists() && fi.size() > maxSize) { QFile::remove(log + ".2"); QFile::rename(log + ".1", log + ".2"); QFile::rename(log, log + ".1"); }
}

void logEvent(const QString &message) {
    rotateLogsIfNeeded();
    QFile f(logFilePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) return;
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    QTextStream out(&f);
    out << QDateTime::currentDateTimeUtc().toString(Qt::ISODate) << " " << message << "\n";
}

static void ensureBalooExclusion() {
    const QString secrets = secretsDirPath();
    const QString baloo = QStandardPaths::findExecutable("balooctl");
    if (!baloo.isEmpty()) {
        runQuiet(baloo, {"config", "add", "excludeFolders", secrets}, nullptr);
        runQuiet(baloo, {"reload"}, nullptr);
    }
    const QString cfgPath = QDir::homePath() + "/.config/baloofilerc";
    QString content;
    QFile cf(cfgPath);
    if (cf.exists()) {
        if (cf.open(QIODevice::ReadOnly | QIODevice::Text)) {
            content = QString::fromUtf8(cf.readAll());
            cf.close();
        }
    }
    if (!content.contains("[General]")) {
        content += "[General]\n";
    }
    const QString line = QStringLiteral("exclude folders[$e]=") + secrets;
    if (!content.contains(line)) {
        if (!content.endsWith('\n')) content += '\n';
        content += line + '\n';
        QSaveFile sf(cfgPath);
        if (sf.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&sf);
            out << content;
            sf.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
            sf.commit();
        }
    }
    if (isMountpointPath(secrets)) {
        QFile nm(secrets + "/.nomedia");
        if (!nm.exists()) {
            if (nm.open(QIODevice::WriteOnly)) {
                nm.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
                nm.close();
            }
        }
    }
}

}

class AutoLockerReceiver : public QObject {
    Q_OBJECT
public:
    using QObject::QObject;
public Q_SLOTS:
    void onActiveChangedMsg(const QDBusMessage &msg) {
        const QString iface = msg.interface();
        const QString member = msg.member();
        const QString sig = msg.signature();
        const bool ifaceOk = (iface == QLatin1String("org.freedesktop.ScreenSaver") || iface == QLatin1String("org.freedesktop.login1.Manager"));
        const bool memberOk = (member == QLatin1String("ActiveChanged") || member == QLatin1String("PrepareForSleep"));
        if (!ifaceOk || !memberOk || !sig.contains('b')) { return; }
        const QString sender = msg.service();
        QStringList owners;
        if (auto si = QDBusConnection::sessionBus().interface()) {
            auto a = si->serviceOwner("org.freedesktop.ScreenSaver"); if (a.isValid()) owners << a.value();
            auto b = si->serviceOwner("org.kde.screensaver"); if (b.isValid()) owners << b.value();
        }
        if (auto sy = QDBusConnection::systemBus().interface()) {
            auto c = sy->serviceOwner("org.freedesktop.login1"); if (c.isValid()) owners << c.value();
        }
        if (!owners.contains(sender)) {
            logEvent(QStringLiteral("dbus_reject: ") + sender);
            return;
        }
        bool active = false;
        const auto args = msg.arguments();
        if (!args.isEmpty()) active = args.at(0).toBool();
        if (active) { QString err; if (tryUnmountPath(secretsDirPath(), &err)) logEvent(QStringLiteral("lock_trigger_dbus")); }
    }
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    struct rlimit rlc{0,0}; setrlimit(RLIMIT_CORE, &rlc);
    prctl(PR_SET_DUMPABLE, 0);
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        logEvent(QStringLiteral("mlockall_failed: ") + QString::fromUtf8(strerror(errno)));
    }

    if (QFileInfo::exists(encryptedDirPath()) && !isDirPermissionsSecure(encryptedDirPath())) {
        logEvent(QStringLiteral("startup_security_fail: insecure encrypted dir"));
        KMessageBox::error(nullptr, QObject::tr("Insecure permissions on: %1").arg(encryptedDirPath()));
        return 1;
    }

    QLockFile lock(runtimeDirPath() + "/secrets-tray.lock");
    lock.setStaleLockTime(0);
    if (!lock.tryLock(100)) {
        qint64 pid = 0; QString host, appname;
        if (lock.getLockInfo(&pid, &host, &appname)) {
            if (pid > 0) return 0;
        }
        lock.removeStaleLockFile();
        if (!lock.tryLock(100)) return 0;
    }
    KStatusNotifierItem tray; tray.setTitle("Secrets"); tray.setCategory(KStatusNotifierItem::ApplicationStatus);
    QMenu *menu = new QMenu(); QAction *toggle = menu->addAction("..."); QAction *manage = menu->addAction(QObject::tr("Manage Secrets…")); menu->addSeparator(); QAction *quit = menu->addAction(QObject::tr("Quit")); tray.setContextMenu(menu); tray.setStandardActionsEnabled(false);

    QObject::connect(quit, &QAction::triggered, &app, &QApplication::quit);
    QObject::connect(&tray, &KStatusNotifierItem::activateRequested, [&tray, toggle](bool /*active*/, const QPoint & /*pos*/){
        if (!isMountpointPath(secretsDirPath())) { toggle->trigger(); return; }
        const QString dolphinPath = QStringLiteral("/usr/bin/dolphin");
        if (!isExecutableTrusted(dolphinPath)) {
            logEvent(QStringLiteral("dolphin binary not trusted"));
            KMessageBox::error(nullptr, QObject::tr("Dolphin not found or untrusted"));
            return;
        }
        QProcess p;
        p.setProgram(dolphinPath);
        p.setArguments({secretsDirPath()});
        p.setProcessEnvironment(safeGuiEnvVars());
        if (!p.startDetached()) {
            logEvent(QStringLiteral("failed to launch dolphin"));
        }
    });
    QObject::connect(manage, &QAction::triggered, [&tray, manage, toggle]() {
        ScopedDialogLock dlgLock(manage, toggle);
        if (!dlgLock.ok()) return;
        {
            QString msg; if (checkLockout(&msg)) { KMessageBox::error(nullptr, msg); return; }
        }
        const int current = readAutolockTimeoutSec();
        bool ok = false;
        int minutes = QInputDialog::getInt(nullptr, QObject::tr("Configure Auto-lock"), QObject::tr("Enter auto-lock timeout (minutes, 1-120). Current: %1").arg(current/60), current/60, 1, 120, 1, &ok);
        if (!ok) return;
        const int idleSecs = minutes * 60; 
        if (!isMountpointPath(secretsDirPath())) {
            bool pwOk = false;
            QByteArray pass = SecurePasswordDialog::getSecurePassword(
                nullptr, 
                QObject::tr("Enter your Secrets password to confirm"),
                &pwOk
            );
            if (!pwOk || pass.isEmpty()) { secure_bzero(pass.data(), (size_t)pass.size()); return; }
            if (!QFileInfo::exists(encryptedDirPath())) { secure_bzero(pass.data(), (size_t)pass.size()); KMessageBox::error(nullptr, QObject::tr("Encrypted directory not found: %1").arg(encryptedDirPath())); return; } 
            if (!isDirPermissionsSecure(encryptedDirPath())) { secure_bzero(pass.data(), (size_t)pass.size()); KMessageBox::error(nullptr, QObject::tr("Insecure permissions on: %1").arg(encryptedDirPath())); return; }
            QTemporaryDir verifier(runtimeDirPath() + "/secrets-verify-XXXXXX"); if (!verifier.isValid()) { secure_bzero(pass.data(), (size_t)pass.size()); KMessageBox::error(nullptr, QObject::tr("Cannot create temporary directory")); return; }
            const QString gbin = findGocryptfsBinary(); QString reason1; QString reason2;
            const bool trusted = isExecutableTrustedDetailed(gbin, &reason1);
            const bool pinned = verifyPinnedBinary("gocryptfs", gbin, &reason2);
            if (!trusted || !pinned) {
                const QString r = (!trusted ? reason1 : reason2).trimmed().isEmpty() ? QStringLiteral("unknown") : (!trusted ? reason1 : reason2);
                logEvent(QStringLiteral("gocryptfs_trust_fail: trusted=%1 pinned=%2 reason=%3").arg(trusted ? QStringLiteral("1") : QStringLiteral("0"), pinned ? QStringLiteral("1") : QStringLiteral("0"), r));
                logTrustDiagnosticsFor(QStringLiteral("gocryptfs"), gbin, QStringLiteral("gocryptfs"));
                secure_bzero(pass.data(), (size_t)pass.size());
                KMessageBox::error(nullptr, QObject::tr("Untrusted gocryptfs binary: %1 (%2).").arg(gbin, r));
                return;
            }
            pass.reserve(pass.size() + 1);
            pass.append('\n'); (void)mlock(pass.data(), (size_t)pass.size());
            QString err; int rc = runWithInput(gbin, {"-q", encryptedDirPath(), verifier.path()}, pass, &err); 
            secure_bzero(pass.data(), (size_t)pass.size()); munlock(pass.data(), (size_t)pass.size());
            if (rc != 0) { logEvent(QStringLiteral("verify_failed: ") + err); recordFailure(); KMessageBox::error(nullptr, QObject::tr("Password verification failed:\n%1").arg(err)); return; }
            tryUnmountPath(verifier.path(), nullptr);
            clearFailuresOnSuccess();
        }
        if (!writeAutolockTimeoutSec(idleSecs)) { logEvent(QStringLiteral("write_timeout_failed")); KMessageBox::error(nullptr, QObject::tr("Failed to write configuration")); return; }
        {
            QFile rf(configFilePath()); QString content;
            if (rf.exists()) { if (!rf.open(QIODevice::ReadOnly | QIODevice::Text)) return; content = QString::fromUtf8(rf.readAll()); rf.close(); }
            QStringList lines = content.split('\n'); bool found=false;
            for (QString &l: lines) {
                if (l.startsWith("GOCryptFS_IDLE_SECS=")) { l = QStringLiteral("GOCryptFS_IDLE_SECS=") + QString::number(idleSecs); found=true; }
            }
            if (!found) lines << QStringLiteral("GOCryptFS_IDLE_SECS=") + QString::number(idleSecs);
            QSaveFile sf(configFilePath()); if (!sf.open(QIODevice::WriteOnly | QIODevice::Text)) return; { QTextStream out(&sf); for (int i=0;i<lines.size();++i) { if (i==lines.size()-1 && lines[i].isEmpty()) continue; out << lines[i] << '\n'; } } sf.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner); sf.commit();
        }
        logEvent(QStringLiteral("timeout_updated: ") + QString::number(minutes) + QStringLiteral("m (idle)"));
    });

    auto isDirEmpty = [](const QString &path) -> bool {
        QFileInfo fi(path);
        if (fi.isSymLink()) return false;
        if (!fi.exists()) return true;
        if (!fi.isDir()) return false;
        if (fi.ownerId() != (uint)getuid()) return false;
        QDir d(path);
        QStringList entries = d.entryList(QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden | QDir::System);
        return entries.isEmpty();
    };
    auto waitForMountpoint = [](const QString &path, bool targetMounted, int timeoutMs = 4000) -> bool { QElapsedTimer t; t.start(); while (t.elapsed() < timeoutMs) { if (isMountpointPath(path) == targetMounted) return true; QThread::msleep(50);} return isMountpointPath(path) == targetMounted; };

    QObject::connect(toggle, &QAction::triggered, [&tray, isDirEmpty, waitForMountpoint, toggle, manage]() {
        ScopedDialogLock dlgLock(toggle, manage);
        if (!dlgLock.ok()) return;
        {
            QString msg; if (checkLockout(&msg)) { KMessageBox::error(nullptr, msg); return; }
        }
        if (isMountpointPath(secretsDirPath())) {
            QString err; if (!tryUnmountPath(secretsDirPath(), &err)) { logEvent(QStringLiteral("lock_failed: ") + err); KMessageBox::error(nullptr, QObject::tr("Failed to lock Secrets:\n%1").arg(err)); } else { waitForMountpoint(secretsDirPath(), /*targetMounted=*/false, 3000); logEvent(QStringLiteral("locked")); }
        } else {
            bool pwOk = false;
            QByteArray pw = SecurePasswordDialog::getSecurePassword(
                nullptr,
                QObject::tr("Enter password to unlock Secrets"),
                &pwOk
            );
            if (!pwOk || pw.isEmpty()) { secure_bzero(pw.data(), (size_t)pw.size()); return; }
            if (!QFileInfo::exists(encryptedDirPath())) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Encrypted directory not found: %1").arg(encryptedDirPath())); return; }
            if (!isDirPermissionsSecure(encryptedDirPath())) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Insecure permissions on: %1").arg(encryptedDirPath())); return; }
            if (!ensurePrivateDir(secretsDirPath())) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Cannot create secure mountpoint: %1").arg(secretsDirPath())); logEvent(QStringLiteral("ensurePrivateDir_failed: ") + secretsDirPath()); return; }
            QString oerr;
            int dfd = openNoFollowDirFd(secretsDirPath(), &oerr);
            if (dfd < 0) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Cannot open mountpoint (security check failed):\n%1").arg(oerr)); logEvent(QStringLiteral("openNoFollowDirFd_failed: ") + oerr); return; }
            QString secErr, emptyErr;
            const bool secureOk = dirFdIsSecureOwned700(dfd, &secErr);
            const bool emptyOk = dirFdIsEmpty(dfd, &emptyErr);
            ::close(dfd);
            if (!secureOk) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Mountpoint security check failed:\n%1").arg(secErr)); logEvent(QStringLiteral("dirFdIsSecureOwned700_failed: ") + secErr); return; }
            if (!emptyOk) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Mountpoint is not empty:\n%1").arg(emptyErr)); logEvent(QStringLiteral("dirFdIsEmpty_failed: ") + emptyErr); return; }
            const QString gbin = findGocryptfsBinary(); QString reason1; QString reason2;
            const bool trusted = isExecutableTrustedDetailed(gbin, &reason1);
            const bool pinned = verifyPinnedBinary("gocryptfs", gbin, &reason2);
            if (!trusted || !pinned) {
                const QString r = (!trusted ? reason1 : reason2).trimmed().isEmpty() ? QStringLiteral("unknown") : (!trusted ? reason1 : reason2);
                logEvent(QStringLiteral("gocryptfs_trust_fail: trusted=%1 pinned=%2 reason=%3").arg(trusted ? QStringLiteral("1") : QStringLiteral("0"), pinned ? QStringLiteral("1") : QStringLiteral("0"), r));
                logTrustDiagnosticsFor(QStringLiteral("gocryptfs"), gbin, QStringLiteral("gocryptfs"));
                secure_bzero(pw.data(), (size_t)pw.size());
                KMessageBox::error(nullptr, QObject::tr("Untrusted gocryptfs binary: %1 (%2).").arg(gbin, r));
                return;
            }
            int idleSecs = 0; { QFile f(configFilePath()); if (f.open(QIODevice::ReadOnly | QIODevice::Text)) { QTextStream in(&f); QRegularExpression re("^GOCryptFS_IDLE_SECS=([0-9]{1,10})$"); while (!in.atEnd()) { const QString line = in.readLine(); if (line.size()>4096) continue; auto m = re.match(line); if (m.hasMatch()) { idleSecs = m.captured(1).toInt(); break; } } } }
            int dfd2 = openNoFollowDirFd(secretsDirPath(), &oerr);
            if (dfd2 < 0) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Mountpoint was modified (security check failed):\n%1").arg(oerr)); logEvent(QStringLiteral("toctou_check_openNoFollowDirFd_failed: ") + oerr); return; }
            const bool secureOk2 = dirFdIsSecureOwned700(dfd2, &secErr);
            const bool emptyOk2 = dirFdIsEmpty(dfd2, &emptyErr);
            ::close(dfd2);
            if (!secureOk2) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Mountpoint was modified (security check failed):\n%1").arg(secErr)); logEvent(QStringLiteral("toctou_check_secureOwned_failed: ") + secErr); return; }
            if (!emptyOk2) { secure_bzero(pw.data(), (size_t)pw.size()); KMessageBox::error(nullptr, QObject::tr("Mountpoint was modified (not empty):\n%1").arg(emptyErr)); logEvent(QStringLiteral("toctou_check_empty_failed: ") + emptyErr); return; }
            QStringList args = {"-q"}; if (idleSecs > 0) { args << "-idle" << (QString::number(idleSecs) + "s"); }
            args << encryptedDirPath() << secretsDirPath();
            pw.reserve(pw.size() + 1);
            pw.append('\n'); (void)mlock(pw.data(), (size_t)pw.size()); 
            QString err; int rc = runWithInput(gbin, args, pw, &err); 
            secure_bzero(pw.data(), (size_t)pw.size()); munlock(pw.data(), (size_t)pw.size());
            if (rc == 0) {
                if (!waitForMountpoint(secretsDirPath(), /*targetMounted=*/true, 10000)) {
                    logEvent(QStringLiteral("unlock_pending"));
                    return;
                }
                ensureBalooExclusion();
                if (idleSecs > 0) setAutolockDeadlineSec(idleSecs); else clearAutolockDeadline();
                logEvent(QStringLiteral("unlocked"));
                clearFailuresOnSuccess();
            }
            else {
                debugLog(QStringLiteral("cmd_debug: ") + gbin + " " + args.join(" "));
                recordFailure();
                waitForMountpoint(secretsDirPath(), /*targetMounted=*/true, 1500);
                if (!isMountpointPath(secretsDirPath())) {
                    const QString msg = err.trimmed().isEmpty() ? QObject::tr("Unknown error (exit code %1)").arg(rc) : err;
                    logEvent(QStringLiteral("unlock_failed: rc=") + QString::number(rc) + QStringLiteral(" err=") + msg);
                    KMessageBox::error(nullptr, QObject::tr("Failed to unlock Secrets:\n%1").arg(msg));
                } else {
                    ensureBalooExclusion();
                    if (idleSecs > 0) setAutolockDeadlineSec(idleSecs); else clearAutolockDeadline();
                    logEvent(QStringLiteral("unlocked"));
                    clearFailuresOnSuccess();
                }
            }
        }
    });

    QObject::connect(&tray, &KStatusNotifierItem::secondaryActivateRequested, [toggle](const QPoint &){ if (isMountpointPath(secretsDirPath())) toggle->trigger(); });

    int cachedTimeout = readAutolockTimeoutSec(); QFileSystemWatcher watcher; watcher.addPath(configFilePath()); QObject::connect(&watcher, &QFileSystemWatcher::fileChanged, [&cachedTimeout, &watcher]() { cachedTimeout = readAutolockTimeoutSec(); watcher.addPath(configFilePath()); });
    QTimer refresh; refresh.setInterval(1000); refresh.start();
    QObject::connect(&refresh, &QTimer::timeout, [&tray, toggle, manage, &cachedTimeout]() {
        static bool lastMounted = false;
        const bool mounted = isMountpointPath(secretsDirPath());
        
        if (mounted != lastMounted) {
            lastMounted = mounted;
        }
        
        const QString icon = mounted ? QStringLiteral("folder-unlocked") : QStringLiteral("folder-locked");
        tray.setIconByName(icon);
        QApplication::setWindowIcon(QIcon::fromTheme(icon));
        toggle->setText(mounted ? QObject::tr("Lock Secrets") : QObject::tr("Unlock Secrets"));
        manage->setVisible(!mounted);
        tray.setStatus(KStatusNotifierItem::Active);
        int idleSecs = 0;
        {
            QFile f(configFilePath());
            if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QTextStream in(&f);
                QRegularExpression re("^GOCryptFS_IDLE_SECS=([0-9]{1,10})$");
                while (!in.atEnd()) { const QString line = in.readLine(); if (line.size()>4096) continue; auto m = re.match(line); if (m.hasMatch()) { idleSecs = m.captured(1).toInt(); break; } }
            }
        }
        tray.setToolTipTitle(QStringLiteral("Secrets"));
        if (mounted) {
            if (idleSecs > 0) {
                qint64 rem = remainingAutolockMs();
                if (rem > 0) {
                    qint64 s = rem / 1000; qint64 m = s / 60; s = s % 60;
                    tray.setToolTipSubTitle(QObject::tr("Auto-lock in %1:%2").arg(QString::number(m), QString::number(s).rightJustified(2, '0')));
                } else {
                    tray.setToolTipSubTitle(QObject::tr("Idle auto-lock: %1m").arg(QString::number(idleSecs/60)));
                }
            } else {
                tray.setToolTipSubTitle(QObject::tr("Unlocked"));
            }
        } else {
            tray.setToolTipSubTitle(QObject::tr("Locked"));
        }
        if (mounted) {
            qint64 rem = remainingAutolockMs();
            if (rem <= 0 && idleSecs > 0) {
                QString err; if (tryUnmountPath(secretsDirPath(), &err)) logEvent(QStringLiteral("autolocked")); else logEvent(QStringLiteral("autolock_failed: ") + err);
            }
        }
        Q_UNUSED(cachedTimeout);
    });

    tray.setStatus(KStatusNotifierItem::Active);
    QApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("folder-locked")));
    static AutoLockerReceiver receiver;
    QDBusConnection::sessionBus().connect("org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver", "org.freedesktop.ScreenSaver", "ActiveChanged", &receiver, SLOT(onActiveChangedMsg(QDBusMessage)));
    QDBusConnection::sessionBus().connect("org.kde.screensaver", "/ScreenSaver", "org.freedesktop.ScreenSaver", "ActiveChanged", &receiver, SLOT(onActiveChangedMsg(QDBusMessage)));
    QDBusConnection::systemBus().connect("org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "PrepareForSleep", &receiver, SLOT(onActiveChangedMsg(QDBusMessage)));
    return app.exec();
}

#include "main.moc"
