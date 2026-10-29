#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QByteArray>
#include <QString>

class QRadioButton;
class QPushButton;
class QPlainTextEdit;
class QLineEdit;
class QGroupBox;
class QLabel;

/*
 * A single loader panel (metldr or lv0ldr): enable checkbox, input/output
 * file pickers, the master key, and the encrypt-only IV / nonce / ekey fields.
 */
class LoaderPanel : public QObject
{
    Q_OBJECT
public:
    LoaderPanel(const QString &title, QWidget *parent);

    QGroupBox *box() const { return m_box; }
    bool isEnabled() const;
    void setEncryptMode(bool encrypt);

    // Runs the operation for this panel. Appends human-readable progress to
    // `log`. Returns true on success.
    bool run(bool encrypt, QString &log);

private slots:
    void browseInput();
    void browseOutput();

private:
    QString m_title;
    QGroupBox *m_box = nullptr;
    QLineEdit *m_inFile = nullptr;
    QLineEdit *m_outFile = nullptr;
    QLineEdit *m_key = nullptr;
    QLineEdit *m_iv = nullptr;
    QLineEdit *m_nonce = nullptr;
    QLineEdit *m_ekey = nullptr;
    QLabel *m_ivLabel = nullptr;
    QLabel *m_nonceLabel = nullptr;
    QLabel *m_ekeyLabel = nullptr;
    bool m_encrypt = false;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void modeChanged();
    void runClicked();

private:
    QRadioButton *m_decRadio = nullptr;
    QRadioButton *m_encRadio = nullptr;
    LoaderPanel *m_metldr = nullptr;
    LoaderPanel *m_lv0ldr = nullptr;
    QPushButton *m_runButton = nullptr;
    QPlainTextEdit *m_log = nullptr;

    bool encryptMode() const;
};

#endif // MAINWINDOW_H
