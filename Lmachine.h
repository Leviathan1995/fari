#pragma once
#ifndef _LMACHINE_H
#define _LMACHINE_H
#include <iostream>
#include <string>
#include <queue>
#include <fstream>
using namespace std;
#define Operand_SIZE 1024 //ֻ��ָ��洢����С 
#define Data_SIZE 1024 //��������С
#define RegisterNum 8   //�Ĵ�����Ŀ
#define PC_Regist 7   //������������±�

boost::regex Regex("(\s)|([0-9]+)|([A-Z_a-z]*[A-Z_a-z0-9]+)|(;)"); //������ʽ
boost::smatch what;
//��ʽ Op data1,data2,data3
enum Operand
{
	//RR
	OpHLT,//CPU��ָͣ�� ��ʽ��HLT
	OpIN,//��һ����д��Register[data1];
	OpOUT,//��Register[data1]�������
	OpADD,
	OpSUB,
	OpMUL,
	OpDIV,
	OpRRMODE,//�Ĵ���Ѱַ��ʽ����
	//RM 
	OpLOAD,//��ȡ
	OpSTORE,//�洢
	OpRMMODE,//�ڴ���Ѱַ
	//RA
	OpLDA,
	OpLDC,
	OpJLT,
	OpJLE,
	OpJGT,
	OpJGE,
	OpJEQ,
	OpJNE,
	OpRAMODE,

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
	IMEM_ERROR,	//IMEM����
	DMEM_ERROR,	//DMEM����
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
	"JLT",
	"JLE",
	"JGT",
	"JGE",
	"JEQ",
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
class Lmachine
{
public:
	/*
	���ݳ�Ա
	*/
	Command OperandMem[Operand_SIZE];//ֻ��ָ��洢��
	int Data[Data_SIZE];//���ݴ洢��
	int Register[RegisterNum];//�Ĵ���
	queue<Token> LmachineToken; //�������ַ���
	fstream Code;//Ҫ���صĻ���ļ�
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
	Result Lad_Instruction(Command * command);
	Result Ldc_Instruction(Command * command);
	Result Jlt_Instruction(Command * command);
	Result Jle_Instruction(Command * command);
	Result Jgt_Instruction(Command * command);
	Result Jge_Instruction(Command * command);
	Result Jeq_Instruction(Command * command);
	Result Jne_Instruction(Command * command);
};

#endif