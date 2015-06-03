#ifndef _GLOBAL_H
#define _GLOBAL_H

#include <string>
#include <boost\regex.hpp>


boost::regex Regex("(\s)|([0-9]+)|([A-Z_a-z]*[A-Z_a-z0-9]+)|(;)"); //������ʽ
boost::smatch what;
typedef unsigned char Bytes; //һ���ֽ�
#define MemSize 256 //������ڴ�

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
//CPU���
struct CPU
{
	Bytes Accumulator;//�ۼ���
	Bytes StackPointer;//��ջָ��SP
	Bytes IndexRegister;//��ַ�Ĵ���
	Bytes InstructionRegister;//ָ��Ĵ���
	Bytes ProgramCounter;//���������
	Bytes BasePointer;//��ַָ��
	bool Carry;//��λ��־��
};
//�����������״̬
enum Status
{
	Running,
	Finished,
	ErrorOp,
	ErrorData,
};
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
	//B ������������ǰ���V ��������������  ����V����[B] ��B��ַ��Ԫ�е�����
	OpHALT,	//CPU��ָͣ�� ��ʽ��HALT
	OpCLEARACC,		//�ۼ�����0
	OpClEARCARRY,	//��λ��־����0
	OpCLEARINDEXREG,//��ַ�Ĵ�����0
	OpINACCD,	//��10������д���ۼ���
	OpINACCB,	//��2������д���ۼ���
	OpINACCA,	//��ascii�ַ�д���ۼ���
	OpOUTACCD,	//���ۼ���������10������ʽ���
	OpOUTACCB,	//���ۼ���������2������ʽ���
	OpOUTACCA,	//���ۼ���������ascii�ַ���ʽ���
	OpINC,//�ۼ�����1��Ӱ���־��
	OpDEC,//�ۼ�����1��Ӱ���־��
	OpINCINDEXREG,//��ַ�Ĵ�����1��Ӱ���־��
	OpDECINDEXREG,//��ַ�Ĵ�����1��Ӱ���־��
	OpACCTOINDEXREG,//�ۼ������������ַ�Ĵ��� x
	OpPUSH,//ѹջ����ջָ���1���ۼ���������ѹ��ջ����
	OpPOP,//��ջ����ջָ���1����ջ������ѹ��ջ��
	OpLAB,//��ʽ LDA B ����B��ַ��Ԫ�е����������ۼ����У��Ե�ǰPC��ָ�ڴ����ֵ��Ϊ��ַƫ��
	OpLAIB,//����ַ�Ĵ���+������B��ָ���ڴ浥Ԫ�����������ۼ��� A=[I+B]
	OpLAVB,//��������B�����ۼ���
	OpLSVB,//��������B�е������͵�SP�Ĵ���
	OpSBA,//[B]=A
	OpSIBA,//[B+I]=A
	//�ӷ�
	OpADDB,//A=A+[B]
	OpADDIB,//A=A+[I+B]
	OpADDVA,//A=A+B
	OpADCB,//A=A+C+[B]
	OpADCIB,//A=A+C+[I+B]
	OpADCVB,//A=A+C+B
	//����
	OpSUBB,//A=A+[B]
	OpSUBIB,//A=A+[I+B]
	OpSUBVA,//A=A+B
	OpSBCB,//A=A+C+[B]
	OpSBCXB,//A=A+C+[I+B]
	OpSBCVB,//A=A+C+B
	//�Ƚ�
	OpCMPB,//A��[B]���ݽ��бȽϣ�Ӱ���־λ
	OpCMPIB,//A��[B+I]���ݽ��бȽϣ�Ӱ���־λ
	OpCMPVP,//A��B�Ƚϣ�Ӱ���־λ
	//��
	OpANDB,//A��[B]������λ�룬Ӱ���־λ
	OpANDVB,//A��Bλ�룬Ӱ���־λ
	OpANDIB,//A��[I+B]λ�룬Ӱ���־λ
	//��


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
