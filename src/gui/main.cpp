#include <QApplication>
#include <QMainWindow>
#include <QScrollArea>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QCheckBox>
#include <QWidget>
#include <QFile>
#include <QDir>
#include <QPushButton>
#include <QTextEdit>
#include <QTabWidget>
#include <QProxyStyle>
#include <QPainter>
#include <QStyleOption>
#include <QFileDialog>
#include <QClipboard>
#include <QMessageBox>
#include <QRegularExpression>
#include <unordered_set>

#include "../vmaware.hpp"

static QString checkmarkSvgPath() {
    const QString path = QDir::tempPath() + "/vmaware_check.svg";
    if (!QFile::exists(path)) {
        QFile f(path);
        if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            f.write("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>"
                    "<polyline points='2,8 6,13 14,4' "
                    "style='fill:none;stroke:#cccccc;stroke-width:2.5;"
                    "stroke-linecap:round;stroke-linejoin:round'/></svg>");
        }
    }
    return path;
}

struct TechniqueRow {
    QFrame*    frame;
    QCheckBox* check;
};

static TechniqueRow makeTechniqueRow(const QString& name) {
    QFrame* row = new QFrame();
    row->setFrameShape(QFrame::StyledPanel);
    row->setFixedHeight(48);
    row->setStyleSheet("background-color: #2a2a2a; border: 1px solid #444; border-radius: 4px;");

    QHBoxLayout* layout = new QHBoxLayout(row);
    layout->setContentsMargins(12, 0, 12, 0);
    layout->setSpacing(10);

    QCheckBox* check = new QCheckBox(row);
    check->setChecked(true);
    check->setFixedSize(22, 22);
    check->setStyleSheet(QString(
        "QCheckBox::indicator { width: 22px; height: 22px; border: 2px solid #666666; border-radius: 3px; background-color: #1e1e1e; }"
        "QCheckBox::indicator:checked { border-color: #666666; background-color: #1e1e1e; image: url(%1); }"
    ).arg(checkmarkSvgPath()));
    layout->addWidget(check);

    QLabel* label = new QLabel(name, row);
    label->setStyleSheet("color: #cccccc; font-size: 13px;");
    layout->addWidget(label);
    layout->addStretch();

    return { row, check };
}

class NoTabFrameStyle : public QProxyStyle {
public:
    using QProxyStyle::QProxyStyle;
    void drawPrimitive(PrimitiveElement element, const QStyleOption* option,
                       QPainter* painter, const QWidget* widget) const override {
        if (element == PE_FrameTabWidget) return;
        QProxyStyle::drawPrimitive(element, option, painter, widget);
    }
};

static QFrame* makeBlankPanel() {
    QFrame* panel = new QFrame();
    panel->setStyleSheet("background-color: #252525; border: 1px solid #3a3a3a;");
    return panel;
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    QMainWindow window;
    window.setWindowTitle("VMAware");
    window.setMinimumSize(1200, 1000);

    QWidget* central = new QWidget();
    central->setStyleSheet("background-color: #1a1a1a;");
    window.setCentralWidget(central);

    QVBoxLayout* outerLayout = new QVBoxLayout(central);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    const QString splitterStyle =
        "QSplitter::handle { background-color: #333333; }"
        "QSplitter::handle:horizontal { width: 1px; }"
        "QSplitter::handle:vertical { height: 1px; }";

    QSplitter* vSplit = new QSplitter(Qt::Vertical, central);
    vSplit->setStyleSheet(splitterStyle);

    QSplitter* hSplit = new QSplitter(Qt::Horizontal, vSplit);
    hSplit->setStyleSheet(splitterStyle);

    // --- top left: scrollable technique list ---
    QScrollArea* scroll = new QScrollArea();
    scroll->setMinimumWidth(900);
    scroll->setWidgetResizable(true);
    scroll->setStyleSheet("background-color: #1e1e1e; border: 1px solid #3a3a3a;");

    QWidget* content = new QWidget();
    content->setStyleSheet("background-color: #1e1e1e;");
    QVBoxLayout* listLayout = new QVBoxLayout(content);
    listLayout->setSpacing(8);
    listLayout->setContentsMargins(16, 16, 16, 16);

    // build rows and keep (frame, checkbox, enum) triples for the Run button
    struct RowEntry { QFrame* frame; QCheckBox* check; VM::enum_flags flag; };
    std::vector<RowEntry> techniqueRows;
    for (const VM::enum_flags flag : VM::technique_vector) {
        auto [frame, check] = makeTechniqueRow(QString::fromStdString(VM::flag_to_string(flag)));
        listLayout->addWidget(frame);
        techniqueRows.push_back({ frame, check, flag });
    }
    listLayout->addStretch();
    scroll->setWidget(content);

    // --- top right: controls panel ---
    QFrame* rightPanel = makeBlankPanel();
    QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(24, 24, 24, 24);
    rightLayout->setSpacing(16);

    const QString btnStyle =
        "QPushButton { background-color: #2e2e2e; color: #cccccc; border: 1px solid #555555;"
        "  border-radius: 4px; padding: 8px 16px; font-size: 13px; text-align: left; }"
        "QPushButton:hover { background-color: #3a3a3a; border-color: #777777; }"
        "QPushButton:pressed { background-color: #252525; }";

    const QString labelStyle = "color: #888888; font-size: 12px;";

    auto makeRow = [&](const char* btnText, const char* labelText) -> QPushButton* {
        QWidget* rowWidget = new QWidget();
        QHBoxLayout* rowLayout = new QHBoxLayout(rowWidget);
        rowLayout->setContentsMargins(0, 0, 0, 0);
        rowLayout->setSpacing(16);

        QPushButton* btn = new QPushButton(btnText, rowWidget);
        btn->setStyleSheet(btnStyle);
        btn->setFixedWidth(140);

        QLabel* lbl = new QLabel(labelText, rowWidget);
        lbl->setStyleSheet(labelStyle);
        lbl->setWordWrap(true);

        rowLayout->addWidget(btn);
        rowLayout->addWidget(lbl, 1);
        rightLayout->addWidget(rowWidget);
        return btn;
    };

    QPushButton* exportBtn      = makeRow("Export",          "Export the results to a file");
    QPushButton* selectAllBtn   = makeRow("Select all",      "Select all techniques in the list");
    QPushButton* deselectAllBtn = makeRow("Deselect all",    "Deselect all techniques in the list");
    QPushButton* resetBtn       = makeRow("Reset defaults",  "Reset techniques to the default selection");
    QPushButton* copyBtn        = makeRow("Copy results",    "Copy the results to clipboard");

    rightLayout->addStretch();

    hSplit->addWidget(scroll);
    hSplit->addWidget(rightPanel);
    hSplit->setStretchFactor(0, 1);
    hSplit->setStretchFactor(1, 2);

    // --- bottom: tabbed panel ---
    QFrame* bottomPanel = makeBlankPanel();
    QVBoxLayout* bottomPanelLayout = new QVBoxLayout(bottomPanel);
    bottomPanelLayout->setContentsMargins(0, 0, 0, 0);
    bottomPanelLayout->setSpacing(0);

    QTabWidget* tabs = new QTabWidget(bottomPanel);
    tabs->setStyle(new NoTabFrameStyle(tabs->style()));
    tabs->setStyleSheet(
        "QTabWidget::pane { border: none; background-color: #252525; top: -1px; }"
        "QTabBar::tab { background-color: #1e1e1e; color: #888888; padding: 6px 20px;"
        "  border: 1px solid #3a3a3a; border-bottom: 1px solid #3a3a3a; margin-right: 2px; }"
        "QTabBar::tab:selected { background-color: #252525; color: #cccccc;"
        "  border-bottom-color: #252525; }"
        "QTabBar::tab:hover:!selected { background-color: #2a2a2a; color: #aaaaaa; }"
    );
    bottomPanelLayout->addWidget(tabs);

    // --- Results tab ---
    QWidget* resultsTab = new QWidget();
    QHBoxLayout* bottomLayout = new QHBoxLayout(resultsTab);
    bottomLayout->setContentsMargins(16, 16, 16, 16);
    bottomLayout->setSpacing(16);

    QTextEdit* resultsBox = new QTextEdit(resultsTab);
    resultsBox->setReadOnly(true);
    resultsBox->setStyleSheet(
        "QTextEdit { background-color: #1e1e1e; color: #cccccc; border: 1px solid #3a3a3a;"
        "  font-family: monospace; font-size: 13px; }"
    );
    resultsBox->setPlaceholderText("Press Run to analyse...");
    bottomLayout->addWidget(resultsBox, 1);

    // right side: large green Run button centered vertically
    QWidget* runArea = new QWidget(resultsTab);
    runArea->setStyleSheet("background: transparent; border: none;");
    QVBoxLayout* runLayout = new QVBoxLayout(runArea);
    runLayout->setContentsMargins(0, 0, 0, 0);
    runLayout->addStretch();

    QPushButton* runBtn = new QPushButton("Run", runArea);
    runBtn->setFixedSize(160, 60);
    runBtn->setStyleSheet(
        "QPushButton { background-color: #2d7a2d; color: #ffffff; border: none;"
        "  border-radius: 6px; font-size: 16px; font-weight: bold; }"
        "QPushButton:hover { background-color: #359435; }"
        "QPushButton:pressed { background-color: #246024; }"
    );
    runLayout->addWidget(runBtn);
    runLayout->addStretch();
    bottomLayout->addWidget(runArea);

    tabs->addTab(resultsTab, "Results");

    vSplit->addWidget(hSplit);
    vSplit->addWidget(bottomPanel);
    vSplit->setStretchFactor(0, 3);
    vSplit->setStretchFactor(1, 3);

    outerLayout->addWidget(vSplit);

    // --- wire up Run button ---
    QObject::connect(runBtn, &QPushButton::clicked, [&]() {
        VM::flagset flags = VM::core::generate_default();

        for (const auto& row : techniqueRows) {
            flags.set(row.flag, row.check->isChecked());
        }

        const VM::vmaware vm(flags);

        auto qs = [](const std::string& s) { return QString::fromStdString(s); };

        QString out;
        out += QString("VM brand:        %1\n").arg(vm.brand.empty()      ? "Unknown" : qs(vm.brand));
        out += QString("VM type:         %1\n").arg(vm.type.empty()       ? "Unknown" : qs(vm.type));
        out += QString("VM likeliness:   %1%\n").arg(vm.percentage);
        out += QString("VM confirmation: %1\n").arg(vm.is_vm              ? "true"    : "false");
        out += QString("VM detections:   %1/%2\n").arg(vm.detected_count).arg(vm.technique_count);
        out += QString("VM hardening:    %1\n").arg(vm.is_hardened        ? "likely"  : "unlikely");
        out += QString("\n===== CONCLUSION: %1 =====\n").arg(qs(vm.conclusion));

        resultsBox->setPlainText(out);

        // colour each row green if detected, red if not
        const std::unordered_set<VM::enum_flags> detectedSet(vm.detected_techniques.begin(), vm.detected_techniques.end());
        for (const auto& row : techniqueRows) {
            if (!row.check->isChecked()) {
                row.frame->setStyleSheet("background-color: #2a2a2a; border: 1px solid #444; border-radius: 4px;");
            } else if (detectedSet.count(row.flag)) {
                row.frame->setStyleSheet("background-color: #1a3a1a; border: 1px solid #3a7a3a; border-radius: 4px;");
            } else {
                row.frame->setStyleSheet("background-color: #3a1a1a; border: 1px solid #7a3a3a; border-radius: 4px;");
            }
        }
    });

    // --- wire up control buttons ---
    QObject::connect(exportBtn, &QPushButton::clicked, [&]() {
        if (resultsBox->toPlainText().isEmpty()) return;
        const QString path = QFileDialog::getSaveFileName(&window, "Export results", "vmaware_results.txt", "Text files (*.txt);;All files (*)");
        if (path.isEmpty()) return;
        QFile f(path);
        if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            f.write(resultsBox->toPlainText().toUtf8());
        } else {
            QMessageBox::warning(&window, "Export failed", "Could not write to " + path);
        }
    });

    QObject::connect(selectAllBtn, &QPushButton::clicked, [&]() {
        for (const auto& row : techniqueRows) {
            row.check->setChecked(true);
        }
    });

    QObject::connect(deselectAllBtn, &QPushButton::clicked, [&]() {
        for (const auto& row : techniqueRows) {
            row.check->setChecked(false);
        }
    });

    QObject::connect(resetBtn, &QPushButton::clicked, [&]() {
        const VM::flagset defaults = VM::core::generate_default();
        for (const auto& row : techniqueRows) {
            row.check->setChecked(defaults.test(row.flag));
        }
    });

    QObject::connect(copyBtn, &QPushButton::clicked, [&]() {
        if (resultsBox->toPlainText().isEmpty()) return;
        QString text = resultsBox->toPlainText();
        text.replace(QRegularExpression(" {2,}"), " ");
        QApplication::clipboard()->setText(text);
    });

    window.show();
    return QApplication::exec();
}
