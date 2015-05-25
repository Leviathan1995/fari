#pragma once
#ifndef _LMACHINE_H
#define _LMACHINE_H
enum Operand
{
	OpHLT,//CPU��ָͣ�� ��ʽ��HLT
	OpIN,//�Ӷ˿ڶ�ȡ����
	OpOUT,//��˿�д����
	OpADD,
	OpSUB,
	OpMUL,
	OpDIV,
	OpRADDRMODE,//�Ĵ���Ѱַ
	OpLOAD,//��ȡ
	OpSTORE,//�洢
	OpMADDRMODE,//�ڴ���Ѱַ

	OpJLT,
	OpJLE,
	OpJGT,
	OpJGE,
	OpJEQ,
	OpJNE,

};
struct Command
{
	Operand op;
	int data1;
	int data2;
	int data3;
};
#endif