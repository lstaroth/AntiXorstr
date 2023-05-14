
import idc
import idaapi
import idautils
import ida_bytes
import ida_ua
import ida_pro

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt
from typing import List

class FunctionModel(QtCore.QAbstractTableModel):
    col_va = 0
    col_size = 1
    col_status = 2
    col_name = 3
    
    class FunctionItem:
        def __init__(self, va, size, name):
            self.va = va
            self.size = size
            self.name = name
            self.status = 0
            self.result = []

    def __init__(self):
        QtCore.QAbstractTableModel.__init__(self)
        self.headerdata = ["VA", "Size", "status", "name"]
        self.mydata = dict()

    def loadFile(self):
        self.va = 0
        self.size = 0
        self.name = ""
        self.status = 0
        self.clear()
        for item in idautils.Functions():
            thisfunc = idaapi.get_func(item)
            flag = idc.get_func_flags(thisfunc.start_ea)
            if (flag & idaapi.FUNC_THUNK) != 0 or (flag & idaapi.FUNC_LIB) != 0:
                continue
            self.addItem(FunctionModel.FunctionItem(thisfunc.start_ea, thisfunc.end_ea - thisfunc.start_ea, idc.get_func_name(thisfunc.start_ea)))
    
    def columnCount(self, index=QtCore.QModelIndex()):
        return len(self.headerdata)

    def rowCount(self, index=QtCore.QModelIndex()):
        return len(self.mydata)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = ...):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return self.headerdata[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        col = index.column()
        if role == Qt.DisplayRole:
            d = list(self.mydata.values())[index.row()]
            if col == self.col_va:
                return hex(d.va)
            if col == self.col_size:
                return d.size
            if col == self.col_status:
                return d.status
            if col == self.col_name:
                return d.name

    def addItem(self, item: FunctionItem):
        self.mydata[item.va] = item
        self.layoutChanged.emit()

    def setItems(self, items: dict):
        self.mydata = items
        self.layoutChanged.emit()

    def clear(self):
        self.mydata = dict()
        self.layoutChanged.emit()

    def clearResult(self, va, size):
        if self.mydata.get(va) == None or self.mydata[va].size != size:
            return
        self.mydata[va].result.clear()

    def addResult(self, va, size, str):
        if self.mydata.get(va) == None or self.mydata[va].size != size:
            return
        self.mydata[va].result.append(str)

    def addResults(self, va, size, strs):
        if self.mydata.get(va) == None or self.mydata[va].size != size:
            return
        for str in strs:
            self.mydata[va].result.append(str)

    def getItemData(self, index):
        return list(self.mydata.values())[index]

    def setStatus(self, va, size, status):
        if self.mydata.get(va) == None or self.mydata[va].size != size:
            return
        self.mydata[va].status = status
        self.layoutChanged.emit()

class ResultModelView(QtCore.QAbstractTableModel):
    def __init__(self):
        QtCore.QAbstractTableModel.__init__(self)
        self.showList = []

    def columnCount(self, index=QtCore.QModelIndex()):
        return 1

    def rowCount(self, index=QtCore.QModelIndex()):
        return len(self.showList)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.DisplayRole:
            return self.showList[index.row()]

    def addItem(self, va, str):
        self.showList.append(va)
        self.layoutChanged.emit()

    def addItem(self, va, str):
        self.showList.append(f"{hex(va)}: {str}")
        self.layoutChanged.emit()

    def addItems(self, va, strs):
        for str in strs:
            self.showList.append(f"{hex(va)}: {str}")
        self.layoutChanged.emit()

    def clear(self):
        self.showList = []
        self.layoutChanged.emit()