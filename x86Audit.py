# -*- coding: utf-8 -*-
# author:R1nd0
# Date:2021-12-09
# Environment:python2.7, x86_64

from idaapi import *
from prettytable import PrettyTable
from functiontable import *


# print function's name
def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Aduiting " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

# get function's addr and check
def getFuncAddr(func_name):
    func_addr = LocByName(func_name)
    if func_addr != BADADDR:
        print printFunc(func_name)
        # print func_name + " Addr : 0x %x" % func_addr
        return func_addr
    return False

# get arg addr
def getArgAddr(start_addr, regNum):
    x86condition = ["jn", "jz" , "jc", "jo", "js", "jp", "jr", "ja", "jb", "jg", "jl"]
    scan_deep = 50
    count = 0
    # get arg's register
    if regNum >= len(regs):
        return BADADDR
    reg = regs[regNum]

    # loop find
    before_addr = RfirstB(start_addr)
    # print "before Addr : 0x %x" % before_addr
    # return BADADDR
    while before_addr != BADADDR:
        # print regNum,GetOpnd(before_addr, 0)
        if reg == GetOpnd(before_addr, 0)[1:1+len(reg)]:
            Mnemonics = GetMnem(before_addr)
            # print Mnemonics
            if Mnemonics[0:2] in x86condition:
                pass
            elif Mnemonics[0:1] == "j":
                pass
            else:
                return before_addr
        count = count + 1
        if count > scan_deep:
            break
        before_addr = RfirstB(before_addr)
        # print "before Addr : 0x %x" % before_addr
    return BADADDR

# get arg
def getArg(start_addr, regNum):
    x86mov = ["mov", "lea"]
    arg_addr = getArgAddr(start_addr, regNum)
    if arg_addr != BADADDR:
        Mnemonics = GetMnem(arg_addr)
        if Mnemonics[0:3] == "add":
            if GetOpnd(arg_addr, 2) == "":
                arg = GetOpnd(arg_addr, 0) + "+" + GetOpnd(arg_addr, 1)
            else:
                arg = GetOpnd(arg_addr, 1) + "+" +  GetOpnd(arg_addr, 2)
        elif Mnemonics[0:3] == "sub":
            if GetOpnd(arg_addr, 2) == "":
                arg = GetOpnd(arg_addr, 0) + "-" + GetOpnd(arg_addr, 1)
            else:
                arg = GetOpnd(arg_addr, 1) + "-" +  GetOpnd(arg_addr, 2)
        elif Mnemonics[0:3] == "xor":
            if GetOpnd(arg_addr, 2) == "":
                arg = GetOpnd(arg_addr, 0) + "^" + GetOpnd(arg_addr, 1)
            else:
                arg = GetOpnd(arg_addr, 1) + "^" +  GetOpnd(arg_addr, 2)
        elif Mnemonics[0:3] == "mul":
            if GetOpnd(arg_addr, 2) == "":
                arg = GetOpnd(arg_addr, 0) + "*" + GetOpnd(arg_addr, 1)
            else:
                arg = GetOpnd(arg_addr, 1) + "*" +  GetOpnd(arg_addr, 2)
        elif Mnemonics[0:3] == "div":
            if GetOpnd(arg_addr, 2) == "":
                arg = GetOpnd(arg_addr, 0) + "/" + GetOpnd(arg_addr, 1)
            else:
                arg = GetOpnd(arg_addr, 1) + "/" +  GetOpnd(arg_addr, 2)
        elif Mnemonics in x86mov:
            arg = GetOpnd(arg_addr, 1)
        else:
            arg = GetDisasm(arg_addr).split("#")[0]
        MakeComm(arg_addr, "addr: 0x%x " % start_addr  + "-------> arg" + str((int(regNum)+1)) + " : " + arg)
        return arg
    else:
        return "get fail"

# audit normal function
def auditAddr(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = GetFunctionAttr(call_addr , FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR :
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in xrange(0,arg_num):
        ret_list.append(getArg(call_addr, num))
    ret_list.append(local_buf_size)
    return ret_list

# get format string
def getFormatString(addr):
    op_num = 1
    # 如果第二个不是立即数则下一个
    if(GetOpType(addr ,op_num) != 5):
        op_num = op_num + 1
    if GetOpType(addr ,op_num) != 5:
        return "get fail"
    op_string = GetOpnd(addr, op_num).split(" ")[1].split("+")[0].split("-")[0].replace("(", "")
    string_addr = LocByName(op_string)
    if string_addr == BADADDR:
        return "get fail"
    string = str(GetString(string_addr))
    # log string
    string_info = []
    string_info.append(op_string)
    string_info.append(string)
    return [string_addr, string_info]

# audit format function
def auditFormat(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = GetFunctionAttr(call_addr, FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        local_buf_size = "NULL"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    for num in xrange(0,arg_num):
        ret_list.append(getArg(call_addr, num))

    #format start
    arg_addr = getArgAddr(call_addr, format_function_offset_dict[func_name])
    string_and_addr = getFormatString(arg_addr)
    format_and_value = []
    if string_and_addr == "get fail":
        ret_list.append("NULL")
    else:
        string_addr = "0x%x" % string_and_addr[0]
        format_and_value.append(string_addr)
        string = string_and_addr[1][1]
        fmt_num = string.count("%")
        format_and_value.append(fmt_num)
        # x86: 6 registers
        if fmt_num > 5:
            fmt_num = fmt_num - format_function_offset_dict[func_name] - 1
        for num in xrange(0, fmt_num):
            if arg_num + num > 5:
                break
            format_and_value.append(getArg(call_addr, arg_num + num))
        ret_list.append(format_and_value)

    string_info = string_and_addr[1]

    print " format String %s: %s"% (string_info[0], string_info[1])
    # ret_list.append([string_addr])
    ret_list.append(local_buf_size)
    return ret_list

# audit function
def audit(func_name):
    # get addr
    func_addr = getFuncAddr(func_name)
    if func_addr == False:
        return False

    # get arg num and set table
    if func_name in one_arg_function:
        arg_num = 1
    elif func_name in two_arg_function:
        arg_num = 2
    elif func_name in three_arg_function:
        arg_num = 3
    elif func_name in format_function_offset_dict:
        arg_num = format_function_offset_dict[func_name] + 1
    else:
        print "The %s function didn't write in the describe arg num of function array,please add it to,such as add to `two_arg_function` arary" % func_name
        return

    # x86call = ["call"]
    # init the table head
    table_head = ["func_name", "addr"]
    for num in xrange(0, arg_num):
        table_head.append("arg" + str(num + 1))
    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)

    # get first call
    # print func_name + " Addr : 0x %x" % func_addr
    # get got addr
    got_addr = DfirstB(func_addr)
    # print "got addr : 0x%x" % got_addr
    # get plt addr
    plt_addr = DfirstB(got_addr)
    # print "plt addr : 0x%x" % plt_addr
    # get call addr
    call_addr = RfirstB(plt_addr)
    while call_addr != BADADDR:
        # set color ———— green (red=0x0000ff,blue = 0xff0000)
        SetColor(call_addr, CIC_ITEM, 0x00ff00)

        Mnemonics = GetMnem(call_addr)
        # print "Mnemonics: " + Mnemonics
        # if Mnemonics in x86call:
        if Mnemonics[0:1] == "c":
            if func_name in format_function_offset_dict:
                info = auditFormat(call_addr, func_name, arg_num)
            else:
                info = auditAddr(call_addr, func_name, arg_num)
            table.add_row(info)
        call_addr = RnextB(plt_addr, call_addr)
    print table


def x86Audit():
    start = '''
           ___    __                   _ _ _   
          / _ \  / /    /\            | (_) |  
    __  _| (_) |/ /_   /  \  _   _  __| |_| |_ 
    \ \/ /> _ <| '_ \ / /\ \| | | |/ _  | | __|
     >  <| (_) | (_) / ____ \ |_| | (_| | | |_ 
    /_/\_\\____/ \___/_/    \_\____|\____|_|\__|
                         code by R1nd0 2021.12
        '''
    print start

    print "Auditing dangerous functions ......"
    for func_name in dangerous_functions:
        audit(func_name)

    print "Auditing attention function ......"
    for func_name in attention_function:
        audit(func_name)

    print "Auditing command execution function ......"
    for func_name in command_execution_function:
        audit(func_name)

    print "Finished! Enjoy the result ~"

if __name__ == "__main__":
    x86Audit();
