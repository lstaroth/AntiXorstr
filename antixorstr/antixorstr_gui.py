
import idc
import idaapi
import idautils
import ida_bytes
import ida_ua

from antixorstr.model import FunctionModel
from antixorstr.model import ResultModelView
from antixorstr.analyze_ui import Ui_AntiXorstr
from antixorstr.antixorstr_core import SearchFunction
from antixorstr.antixorstr_core import InitAntixorstrCore
from antixorstr.antixorstr_utils import SetDebuginfo

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QMessageBox, QVBoxLayout, QMenu
from PyQt5.QtGui import QCursor, QKeySequence

PLUGIN_NAME = "AntiXorstr (x86/x64)"
PLUGIN_HOTKEY = 'ctrl+alt+a'
VERSION = 'V2.1'
WINDOWTITLE = f'{PLUGIN_NAME} {VERSION}'

class AntixorstrGui(idaapi.plugin_t):
    """
    Main Plugin Class
    """
    flags = idaapi.PLUGIN_KEEP
    comment = "Analyze all XorStr with plugin"
    help = f"Edit->Plugin->antixorstr"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    windows = None
    
    def __init__(self):
        super(AntixorstrGui, self).__init__()
        pass
    
    def init(self):#相当于构造函数
        return idaapi.PLUGIN_OK
 
    def term(self):#相当于析构函数
        return idaapi.PLUGIN_OK

    def run(self, arg):
        OpenForm()
        pass

def OpenForm():
    """
    open the same form, no matter how the plugin is launched
    """
    global function_form
    try:
        function_form
    except:
        function_form = FunctionsListForm()
    function_form.Show()

class FunctionsListForm(idaapi.PluginForm):
    def OnCreate(self, form):
        if form is None:
                return None
        self.parent = self.FormToPyQtWidget(form)
        self.mtw = AnalyzeWidget()
        self.mtw.setWindowTitle(WINDOWTITLE)
        
        layout = QVBoxLayout()
        layout.addWidget(self.mtw)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass

    def Show(self):
        return idaapi.PluginForm.Show(self, WINDOWTITLE, options=idaapi.PluginForm.WOPN_PERSIST)

class AnalyzeWidget(QtWidgets.QWidget, Ui_AntiXorstr):
    def __init__(self):
        super(AnalyzeWidget,self).__init__()
        self.setupUi(self)
        self.retranslateUi(self)

        self.function_model = FunctionModel()
        self.result_model = ResultModelView()
        self.result_tableview.setModel(self.result_model)
        self.function_tableview.setModel(self.function_model)

        self.function_tableview.resizeColumnsToContents()
        self.function_tableview.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.function_tableview.setSelectionMode(QtWidgets.QTableView.SingleSelection)
        self.function_tableview.setEditTriggers(QtWidgets.QTableView.NoEditTriggers)
        self.function_tableview.setContextMenuPolicy(Qt.CustomContextMenu)
        self.function_tableview.horizontalHeader().setStretchLastSection(True)
        self.function_tableview.setAlternatingRowColors(True)
        self.result_tableview.horizontalHeader().setVisible(False)
        self.result_tableview.horizontalHeader().setStretchLastSection(True)

        self.load_button.clicked.connect(self.LoadButtonClick)
        self.function_tableview.clicked.connect(self.FunctionTableviewClick)
        self.function_tableview.doubleClicked.connect(self.FunctionTableviewDoubleClick)
        self.this_button.clicked.connect(self.ThisButtonClick)
        self.all_button.clicked.connect(self.AllButtonClick)

    def LoadButtonClick(self):
        self.function_model.loadFile()
        if "0x" not in self.load_lineedit.text():
            InitAntixorstrCore(0, 0)
        else:
            InitAntixorstrCore(int(self.load_lineedit.text(), 16), self.bit_checkbox.isChecked())

    def FunctionTableviewClick(self, index):
        item_data = self.function_model.getItemData(index.row())
        self.start_lineedit.setText(hex(item_data.va))
        self.end_lineedit.setText(hex(item_data.va + item_data.size))

    def FunctionTableviewDoubleClick(self, index):
        if not index.isValid():
            return None
        idaapi.jumpto(self.function_model.getItemData(index.row()).va)
        return None

    def ThisButtonClick(self):
        if "0x" not in self.start_lineedit.text() or "0x" not in self.end_lineedit.text():
            QMessageBox.information(self, "Tips","please set function range first", QMessageBox.Yes|QMessageBox.No, QMessageBox.Yes)
            return

        SetDebuginfo(self.debuginfo_checkbox.isChecked())
        start_ea = int(self.start_lineedit.text(), 16)
        end_ea = int(self.end_lineedit.text(), 16)

        status, real_str = SearchFunction(start_ea, end_ea)

        self.function_model.setStatus(start_ea, end_ea - start_ea, status)
        self.function_model.clearResult(start_ea, end_ea - start_ea)
        self.function_model.addResults(start_ea, end_ea - start_ea, real_str)

        self.result_model.clear()
        self.result_model.addItems(start_ea, real_str)

    def AllButtonClick(self):
        if self.debuginfo_checkbox.isChecked():
            QMessageBox.information(self, "Tips","debuginfo output do not support all function", QMessageBox.Yes|QMessageBox.No, QMessageBox.Yes)
            self.debuginfo_checkbox.setChecked(False)

        SetDebuginfo(False)
        self.result_model.clear()

        for va in self.function_model.mydata.keys():
            if self.function_model.mydata[va].status == 0:
                status, real_str = SearchFunction(va, self.function_model.mydata[va].va + self.function_model.mydata[va].size)
                self.function_model.mydata[va].status = status
                self.function_model.addResults(va, self.function_model.mydata[va].size, real_str)
            self.result_model.addItems(va, self.function_model.mydata[va].result)