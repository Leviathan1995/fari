#pragma once
#ifndef _LMACHINE_H
#define _LMACHINE_H
#include "Global.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
using namespace std;
#define Operand_SIZE 1024 //ֻ��ָ��洢����С 
#define Data_SIZE 1024 //��������С
#define RegisterNum 8   //�Ĵ�����Ŀ
#define PC_Register 7   //������������±�

boost::regex Regex("(\s)|([0-9]+)|([A-Z_a-z]*[A-Z_a-z0-9]+)|(;)"); //������ʽ
boost::smatch what;
//��ʽ Op data1,data2,data3
enum Operand
{
	//RR
	OpHALT,	//CPU��ָͣ�� ��ʽ��HALT
	OpIN,	//��һ����д��Register[data1] 
	OpOUT,	//��Register[data1]�������
	OpADD,
	OpSUB,
	OpMUL,
	OpDIV,
	OpRRMODE,//RR����ָ������
	//RM 
	OpLOAD,	//���ڴ���Data[Register[num2]+num3] �浽Register[num1]
	OpSTORE,//��Register[num1]�浽Data[Register[num2]+num3]
	OpRMMODE,//RM����ָ������
	//RA
	OpLDA,	//load regs[s]+t into regs[r]
	OpLDC,	// load t into regs[r]
	OpJL,	//<
	OpJLE,	//<=
	OpJNLE,	//>
	OpJNL,	//>=
	OpJE,	//==
	OpJNE,	//!=
	OpRAMODE,//RA����ָ������

};
enum OpCode //���ֲ�ͬ���͵�opcode
{
	OperandRR,
	OperandRM,
	OperandRA,
};
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
string OpCodeTable[] =
{
	//RR
	"HLT",
	"IN",
	"OUT",
	"ADD",
	"SUB",
	"MUL",
	"DIV",
	"????"
	//RM
	"LD",
	"ST",
	"????",
	//RA
	"LDA",
	"LDC",
	"JL",
	"JLE",
	"JNLE",
	"JNL",
	"JE",
	"JNE",
	"????",
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
class Token
{
public:
	Token();
	Token(int number);
	Token(string ID);
	string ID;
	int Number;
	bool IsID();
	bool IsNumber();
	string GetID();
	string GetNumber();
};
//�����
class Assembler
{
public:
	/*
		���ݳ�Ա
	*/
	vector<Token> LmachineToken; //�������ַ���
	vector<Symbol> SymbolTable;//���ű�̬����
	/*
		��Ա����
	*/
	Assembler();
	Assembler(vector<Token> *token,Lmachine *lmachine);
	~Assembler();
	void Run_Assembler();	//���л����
	void BuildSymbolTable();//�������ű�
	bool SearchSymbol(string symbolname);//�ڷ��ű��в��ҷ���
	TokenType Lexer(Token token);//ȷ��Token������
};
//�����
class Lmachine
{
public:
	/*
	���ݳ�Ա
	*/
	Command OperandMem[Operand_SIZE];//ֻ��ָ��洢��
	Bytes Data[Data_SIZE];//���ݴ洢��
	int Register[RegisterNum];//�Ĵ���
	vector<Token> LmachineToken; //�������ַ���
	fstream *Code;//Ҫ���صĻ���ļ�
	int IADDR_Pointer;//ָ��ֻ��ָ��洢����ָ��
	int DADDR_Pointer;//ָ�����ݴ洢����ָ��
	/*
	��Ա����
	*/
	void Init();//��ʼ��
	void Load();//���ػ����뵽ֻ��ָ��洢��
	void Run();//���������
	void ReadLine();//��FILE����Code���ֶ�ȡ��LmachineToken��
	string Error(string error);//���������Ϣ
	Operand Token2Op(Token token);//��Tokenת��Ϊö�����͵�Operand
	int Token2Int(Token token);
	int OpClass(int c);//����c��ֵ��Operandö�ٲ���ָ�������
	Result OpRun(Command * command);//����ִ��
	Result In_Instruction(Command * command);
	Result Out_Instruction(Command * command);
	Result Add_Instruction(Command * command);
	Result Sub_Instruction(Command * command);
	Result Mul_Instruction(Command * command);
	Result Div_Instruction(Command * command);
	Result Load_Instruction(Command * command);
	Result Store_Instruction(Command * command);
	Result Lda_Instruction(Command * command);
	Result Ldc_Instruction(Command * command);
	Result Jl_Instruction(Command * command);
	Result Jle_Instruction(Command * command);
	Result Jnle_Instruction(Command * command);
	Result Jnl_Instruction(Command * command);
	Result Je_Instruction(Command * command);
	Result Jne_Instruction(Command * command);
};

#endif
