//
//  main.cpp
//  Lmachine
//
//  Created by leviathan on 15/8/21.
//  Copyright (c) 2015年 leviathan. All rights reserved.
//

#include <iostream>
#include "assembler.h"
#include "lmachine.h"
#include "token.h"
using namespace std;

int main() {
    Lmachine lvm;
    lvm.init(); //init lmachine
    lvm.readline();
    Tokenparse token;
}