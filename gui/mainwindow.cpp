#include "mainwindow.h"

#include <QWidget>
#include <QGroupBox>
#include <QRadioButton>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QMessageBox>
#include <QRegularExpression>

#include <cstdlib>

extern "C" {
#include "spucore.h"
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Parse a hex string into exactly `expectedBytes` bytes. Returns true on
// success and fills `out`; otherwise returns false and sets `err`.
static bool parseHex(const QString &text, int expectedBytes, QByteArray &out, QString &err)
{
    QString s = text.trimmed();
    s.remove(QRegularExpression("\\s"));
    if (s.isEmpty()) {
        err = "field is empty";
        return false;
    }
    if (s.size() % 2 != 0) {
        err = "odd number of hex digits";
        return false;
    }
    static const QRegularExpression hexRe("^[0-9a-fA-F]*$");
    if (!hexRe.match(s).hasMatch()) {
        err = "contains non-hex characters";
        return false;
    }
    QByteArray bytes = QByteArray::fromHex(s.toLatin1());
    if (bytes.size() != expectedBytes) {
        err = QString("expected %1 bytes (%2 hex digits), got %3")
                  .arg(expectedBytes).arg(expectedBytes * 2).arg(bytes.size());
        return false;
    }
    out = bytes;
    return true;
}

// ---------------------------------------------------------------------------
// LoaderPanel
// ---------------------------------------------------------------------------

LoaderPanel::LoaderPanel(const QString &title, QWidget *parent)
    : QObject(parent), m_title(title)
{
    m_box = new QGroupBox(title, parent);
    m_box->setCheckable(true);
    m_box->setChecked(true);

    auto *form = new QFormLayout(m_box);

    // Input file row
    m_inFile = new QLineEdit(m_box);
    auto *inBrowse = new QPushButton("Browse…", m_box);
    auto *inRow = new QHBoxLayout();
    inRow->addWidget(m_inFile);
    inRow->addWidget(inBrowse);
    form->addRow("Input file", inRow);

    // Output file row
    m_outFile = new QLineEdit(m_box);
    auto *outBrowse = new QPushButton("Browse…", m_box);
    auto *outRow = new QHBoxLayout();
    outRow->addWidget(m_outFile);
    outRow->addWidget(outBrowse);
    form->addRow("Output file", outRow);

    // Key
    m_key = new QLineEdit(m_box);
    m_key->setPlaceholderText("32 hex digits (16-byte AES-128 key)");
    form->addRow("Master key", m_key);

    // Encrypt-only fields
    m_iv = new QLineEdit(m_box);
    m_iv->setPlaceholderText("24 hex digits (12-byte IV)");
    m_ivLabel = new QLabel("IV", m_box);
    form->addRow(m_ivLabel, m_iv);

    m_nonce = new QLineEdit(m_box);
    m_nonce->setPlaceholderText("24 hex digits (12-byte console nonce)");
    m_nonceLabel = new QLabel("Nonce", m_box);
    form->addRow(m_nonceLabel, m_nonce);

    m_ekey = new QLineEdit(m_box);
    m_ekey->setPlaceholderText("32 hex digits (16-byte scramble/ekey)");
    m_ekeyLabel = new QLabel("EKey", m_box);
    form->addRow(m_ekeyLabel, m_ekey);

    connect(inBrowse, &QPushButton::clicked, this, &LoaderPanel::browseInput);
    connect(outBrowse, &QPushButton::clicked, this, &LoaderPanel::browseOutput);

    setEncryptMode(false);
}

bool LoaderPanel::isEnabled() const
{
    return m_box->isChecked();
}

void LoaderPanel::setEncryptMode(bool encrypt)
{
    m_encrypt = encrypt;
    m_iv->setVisible(encrypt);
    m_nonce->setVisible(encrypt);
    m_ekey->setVisible(encrypt);
    m_ivLabel->setVisible(encrypt);
    m_nonceLabel->setVisible(encrypt);
    m_ekeyLabel->setVisible(encrypt);
}

void LoaderPanel::browseInput()
{
    QString f = QFileDialog::getOpenFileName(m_box, m_title + ": select input file");
    if (f.isEmpty())
        return;
    m_inFile->setText(f);
    if (m_outFile->text().trimmed().isEmpty()) {
        m_outFile->setText(f + (m_encrypt ? ".enc" : ".dec"));
    }
}

void LoaderPanel::browseOutput()
{
    QString f = QFileDialog::getSaveFileName(m_box, m_title + ": select output file");
    if (!f.isEmpty())
        m_outFile->setText(f);
}

bool LoaderPanel::run(bool encrypt, QString &log)
{
    const QString tag = "[" + m_title + "] ";

    const QString inPath = m_inFile->text().trimmed();
    const QString outPath = m_outFile->text().trimmed();
    if (inPath.isEmpty() || outPath.isEmpty()) {
        log += tag + "ERROR: input and output file paths are required.\n";
        return false;
    }

    QString err;
    QByteArray key;
    if (!parseHex(m_key->text(), 16, key, err)) {
        log += tag + "ERROR: master key " + err + ".\n";
        return false;
    }

    QByteArray iv, nonce, ekey;
    if (encrypt) {
        if (!parseHex(m_iv->text(), 12, iv, err)) {
            log += tag + "ERROR: IV " + err + ".\n";
            return false;
        }
        if (!parseHex(m_nonce->text(), 12, nonce, err)) {
            log += tag + "ERROR: nonce " + err + ".\n";
            return false;
        }
        if (!parseHex(m_ekey->text(), 16, ekey, err)) {
            log += tag + "ERROR: ekey " + err + ".\n";
            return false;
        }
    }

    QFile inFile(inPath);
    if (!inFile.open(QIODevice::ReadOnly)) {
        log += tag + "ERROR: cannot open input file: " + inFile.errorString() + "\n";
        return false;
    }
    QByteArray input = inFile.readAll();
    inFile.close();

    unsigned char *out = nullptr;
    size_t outLen = 0;
    int rc;

    if (encrypt) {
        rc = spu_encrypt_buffer(
            reinterpret_cast<const unsigned char *>(key.constData()),
            reinterpret_cast<const unsigned char *>(iv.constData()),
            reinterpret_cast<const unsigned char *>(nonce.constData()),
            reinterpret_cast<const unsigned char *>(ekey.constData()),
            reinterpret_cast<const unsigned char *>(input.constData()),
            static_cast<size_t>(input.size()),
            &out, &outLen);
    } else {
        rc = spu_decrypt_buffer(
            reinterpret_cast<const unsigned char *>(key.constData()),
            reinterpret_cast<const unsigned char *>(input.constData()),
            static_cast<size_t>(input.size()),
            &out, &outLen);
    }

    if (rc != SPU_OK) {
        QString reason;
        switch (rc) {
        case SPU_ERR_MAC:       reason = "MAC verification failed (wrong key or corrupted container)"; break;
        case SPU_ERR_TOO_SMALL: reason = "input too small to contain a valid 64-byte header"; break;
        case SPU_ERR_ALLOC:     reason = "out of memory"; break;
        case SPU_ERR_CRYPTO:    reason = "crypto engine failure"; break;
        default:                reason = QString("error code %1").arg(rc); break;
        }
        log += tag + (encrypt ? "ENCRYPT FAILED: " : "DECRYPT FAILED: ") + reason + ".\n";
        if (out) free(out);
        return false;
    }

    QByteArray result(reinterpret_cast<const char *>(out), static_cast<int>(outLen));
    free(out);

    QFile outFile(outPath);
    if (!outFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        log += tag + "ERROR: cannot open output file: " + outFile.errorString() + "\n";
        return false;
    }
    outFile.write(result);
    outFile.close();

    if (encrypt) {
        QByteArray mac = result.mid(0x30, 16);
        log += tag + QString("OK: encrypted %1 → %2 (%3 bytes). MAC=%4\n")
                         .arg(QFileInfo(inPath).fileName())
                         .arg(QFileInfo(outPath).fileName())
                         .arg(result.size())
                         .arg(QString::fromLatin1(mac.toHex()));
    } else {
        log += tag + QString("OK: MAC verified. Decrypted %1 → %2 (%3 bytes).\n")
                         .arg(QFileInfo(inPath).fileName())
                         .arg(QFileInfo(outPath).fileName())
                         .arg(result.size());
    }
    return true;
}

// ---------------------------------------------------------------------------
// MainWindow
// ---------------------------------------------------------------------------

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("spu_iso_tool — lv0ldr / metldr");

    auto *central = new QWidget(this);
    auto *root = new QVBoxLayout(central);

    // Mode selector
    auto *modeBox = new QGroupBox("Operation", central);
    auto *modeLayout = new QHBoxLayout(modeBox);
    m_decRadio = new QRadioButton("Decrypt", modeBox);
    m_encRadio = new QRadioButton("Encrypt", modeBox);
    m_decRadio->setChecked(true);
    modeLayout->addWidget(m_decRadio);
    modeLayout->addWidget(m_encRadio);
    modeLayout->addStretch();
    root->addWidget(modeBox);

    // Loader panels, side by side
    m_metldr = new LoaderPanel("metldr", central);
    m_lv0ldr = new LoaderPanel("lv0ldr", central);
    auto *panels = new QHBoxLayout();
    panels->addWidget(m_metldr->box());
    panels->addWidget(m_lv0ldr->box());
    root->addLayout(panels);

    // Run button
    m_runButton = new QPushButton("Run", central);
    auto *runRow = new QHBoxLayout();
    runRow->addStretch();
    runRow->addWidget(m_runButton);
    root->addLayout(runRow);

    // Log
    m_log = new QPlainTextEdit(central);
    m_log->setReadOnly(true);
    m_log->setMinimumHeight(140);
    root->addWidget(m_log);

    setCentralWidget(central);

    connect(m_decRadio, &QRadioButton::toggled, this, &MainWindow::modeChanged);
    connect(m_encRadio, &QRadioButton::toggled, this, &MainWindow::modeChanged);
    connect(m_runButton, &QPushButton::clicked, this, &MainWindow::runClicked);

    modeChanged();
    resize(760, 520);
}

bool MainWindow::encryptMode() const
{
    return m_encRadio->isChecked();
}

void MainWindow::modeChanged()
{
    const bool enc = encryptMode();
    m_metldr->setEncryptMode(enc);
    m_lv0ldr->setEncryptMode(enc);
    m_runButton->setText(enc ? "Encrypt" : "Decrypt");
}

void MainWindow::runClicked()
{
    const bool enc = encryptMode();

    if (!m_metldr->isEnabled() && !m_lv0ldr->isEnabled()) {
        QMessageBox::warning(this, "Nothing to do",
                             "Enable at least one loader (metldr and/or lv0ldr).");
        return;
    }

    QString log;
    int ran = 0, ok = 0;

    if (m_metldr->isEnabled()) {
        ++ran;
        if (m_metldr->run(enc, log)) ++ok;
    }
    if (m_lv0ldr->isEnabled()) {
        ++ran;
        if (m_lv0ldr->run(enc, log)) ++ok;
    }

    log += QString("\nFinished: %1/%2 succeeded.\n").arg(ok).arg(ran);
    m_log->appendPlainText(log);

    if (ok == ran) {
        QMessageBox::information(this, "Done",
                                 QString("%1 of %2 operation(s) succeeded.").arg(ok).arg(ran));
    } else {
        QMessageBox::warning(this, "Completed with errors",
                             QString("%1 of %2 operation(s) succeeded. See the log for details.")
                                 .arg(ok).arg(ran));
    }
}
