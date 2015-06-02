#pragma once
#ifndef _LMACHINE_H
#define _LMACHINE_H
#include "Global.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
using namespace std;


enum Result
{
	OK,		//��ȷִ��
	HALT,	//ִֹͣ��
	OperandMEM_ERROR,	//IMEM����
	DataMEM_ERROR,	//DMEM����
	ZERO_ERROR,//�������
	NONECOMMAND_ERROR,//ָ�����
};
struct Command
{
	Operand op;
	int data1;	//r
	int data2;	//s
	int data3;	//t
};

string ResultTable[] =
{
	"OK",
	"HLT"
	"INSTRUCTION MEMORY FAULT",
	"DATA MEMORY FAULT",
	"DIVISION BY 0"
};
//ͬ�����ý��
struct SymbolReferenceNode
{
	Bytes ReferenceAddr;	   //ͬ�����õķ��ŵ��ڴ��ַ
	SymbolReferenceNode * Next;//��һ��ͬ�����õĽ��
};
//���Ŷ���
struct Symbol
{
	string SymbolName;	//���ŵ�ַ��
	Bytes SymbolAddr;	//�����ڴ��ַ
	SymbolReferenceNode * First;//�÷����״γ���
};


//�����
class Lmachine
{
public:
	/*
		���ݳ�Ա
	*/
	Bytes Memory[MemSize];//������ڴ�ռ�

	/*
		��Ա����
	*/
	void Init();//��ʼ��
	inline string GetMemonic(int i) //���ػ���ָ��i�����Ƿ�
	{
		return  OpMemonic[i];
	}


};

#endif
