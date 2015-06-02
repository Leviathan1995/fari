#ifndef _GLOBAL_H
#define _GLOBAL_H

#include <string>
#include <boost\regex.hpp>


boost::regex Regex("(\s)|([0-9]+)|([A-Z_a-z]*[A-Z_a-z0-9]+)|(;)"); //������ʽ
boost::smatch what;
typedef unsigned char Bytes; //һ���ֽ�
#define MemSize 256 //������ڴ�

//�����ַ���
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
	int GetNumber();
};
//�ַ�������
enum TokenType
{
	ASMCode,
	Lablel,
	ReferLabel,
	Number,
	ID,
	UnKnown
};
//���������ָ���
enum Operand
{
	OpHALT,	//CPU��ָͣ�� ��ʽ��HALT
	OpIN,	//��һ����д��Register[data1] 
	OpOUT,	//��Register[data1]�������
	OpADD,
	OpSUB,
	OpMUL,
	OpDIV,
	OpINC,//+1
	OpDEC,//-1
	OpPUSH,
	OpPOP,
	OpCMP,
	OpJMP,
	OpLOAD,	//���ڴ���Data[Register[num2]+num3] �浽Register[num1]
	OpSTORE,//��Register[num1]�浽Data[Register[num2]+num3]
	OpLDA,	//load regs[s]+t into regs[r]
	OpLDC,	// load t into regs[r]
	OpJL,	//<
	OpJLE,	//<=
	OpJNLE,	//>
	OpJNL,	//>=
	OpJE,	//==
	OpJNE,	//!=
	OpError,//����ָ��

};
//ָ�����Ƿ�
string OpMemonic[] =
{
	"HALT",
	"IN",
	"OUT",
	"ADD",
	"SUB",
	"MUL",
	"DIV",
	"INC"
	"DEC"
	"PUSH"
	"POP"
	"CMP"
	"JMP"
	"LOAD",
	"STORE",
	"LDA",
	"LDC",
	"JL",
	"JLE",
	"JNLE",
	"JNL",
	"JE",
	"JNE",
};
#endif
