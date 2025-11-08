#pragma once

#include <QDialog>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QVector>
#include <cstring>

#if defined(__GLIBC__)
#include <string.h>
#else
static inline void explicit_bzero(void *s, size_t n) {
    volatile unsigned char *p = reinterpret_cast<volatile unsigned char*>(s);
    while (n--) *p++ = 0;
}
#endif

class SecureLineEdit : public QLineEdit {
    Q_OBJECT
public:
    explicit SecureLineEdit(QWidget *parent = nullptr) : QLineEdit(parent) {
        setEchoMode(QLineEdit::Password);
        setContextMenuPolicy(Qt::NoContextMenu);
        setAttribute(Qt::WA_InputMethodEnabled, false);
    }

    QByteArray getPasswordBytes() const {
        QByteArray result;
        result.reserve(m_buffer.size());
        for (char c : m_buffer) {
            result.append(c);
        }
        return result;
    }

    void clearSecure() {
        if (!m_buffer.isEmpty()) {
            explicit_bzero(m_buffer.data(), static_cast<size_t>(m_buffer.size()));
            m_buffer.clear();
        }
        clear();
    }

protected:
    void keyPressEvent(QKeyEvent *event) override {
        if (event->key() == Qt::Key_Backspace) {
            if (!m_buffer.isEmpty()) {
                explicit_bzero(&m_buffer.last(), sizeof(char));
                m_buffer.removeLast();
                setText(QString(m_buffer.size(), '*'));
            }
            event->accept();
            return;
        }
        
        if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
            QLineEdit::keyPressEvent(event);
            return;
        }

        QString text = event->text();
        if (!text.isEmpty() && text[0].isPrint()) {
            QByteArray utf8 = text.toUtf8();
            for (int i = 0; i < utf8.size(); ++i) {
                m_buffer.append(utf8[i]);
            }
            if (utf8.data() != nullptr && utf8.size() > 0) {
                explicit_bzero(utf8.data(), static_cast<size_t>(utf8.size()));
            }
            setText(QString(m_buffer.size(), '*'));
            event->accept();
        } else {
            event->ignore();
        }
    }

private:
    QVector<char> m_buffer;
};

class SecurePasswordDialog : public QDialog {
    Q_OBJECT

public:
    explicit SecurePasswordDialog(QWidget *parent = nullptr, const QString &prompt = QString())
        : QDialog(parent)
    {
        setWindowTitle(tr("Password Required"));
        setModal(true);
        setWindowIcon(QIcon::fromTheme(QStringLiteral("folder-locked")));

        auto *layout = new QVBoxLayout(this);

        m_label = new QLabel(prompt.isEmpty() ? tr("Enter password:") : prompt, this);
        layout->addWidget(m_label);

        m_lineEdit = new SecureLineEdit(this);
        layout->addWidget(m_lineEdit);

        auto *buttonLayout = new QHBoxLayout();
        buttonLayout->addStretch();

        m_okButton = new QPushButton(tr("OK"), this);
        m_okButton->setDefault(true);
        connect(m_okButton, &QPushButton::clicked, this, &QDialog::accept);
        buttonLayout->addWidget(m_okButton);

        m_cancelButton = new QPushButton(tr("Cancel"), this);
        connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
        buttonLayout->addWidget(m_cancelButton);

        layout->addLayout(buttonLayout);
    }

    ~SecurePasswordDialog() override {
        m_lineEdit->clearSecure();
    }

    static QByteArray getSecurePassword(QWidget *parent, const QString &prompt, bool *ok = nullptr) {
        SecurePasswordDialog dlg(parent, prompt);
        bool accepted = (dlg.exec() == QDialog::Accepted);
        if (ok) *ok = accepted;

        if (!accepted) {
            dlg.m_lineEdit->clearSecure();
            return QByteArray();
        }

        QByteArray password = dlg.m_lineEdit->getPasswordBytes();
        dlg.m_lineEdit->clearSecure();

        if (password.isEmpty()) {
            if (password.data() != nullptr && password.size() > 0) {
                explicit_bzero(password.data(), static_cast<size_t>(password.size()));
            }
            return QByteArray();
        }
        return password;
    }

private:
    QLabel *m_label;
    SecureLineEdit *m_lineEdit;
    QPushButton *m_okButton;
    QPushButton *m_cancelButton;
};
