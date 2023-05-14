import sys
from antixorstr.antixorstr_gui import AntixorstrGui
    
__AUTHOR__ = 'https://github.com/lstaroth'
 
# register IDA plugin
def PLUGIN_ENTRY():
    return AntixorstrGui()
    