//
//  lmachine.h
//  Lmachine
//
//  Created by leviathan on 15/8/21.
//  Copyright (c) 2015年 leviathan. All rights reserved.
//

#pragma once
#ifndef __Lvm__lmachine__
#define __Lvm__lmachine__

#include <iostream>
#include <vector>
#include <string>
#include "global.h"

using namespace std;


//virtual machine
class Lmachine
{
public:
    //funciton
    Lmachine();
    bool init();
    void initreg(); // init register
    void lvmrun();
    void readline();
    char * string2char(string str);
    int string2int(string str);
    int getregindex(MemoryNode reg);
    int getcmdindex(MemoryNode cmd);
    int getint(MemoryNode mem);
    void regoperand(int regindex,regop op,int num);
    //data
    cpu lvmcpu;
    status lvmstatus;
    static string infile;
    static string outfile;
    
};
#endif /* defined(__Lvm__lmachine__) */
