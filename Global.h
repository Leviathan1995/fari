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
	Bytes Accumulator;//�ۼ���,���AX
	Bytes StackPointer;//��ջָ��SP�����SP
	Bytes IndexRegister;//��ַ�Ĵ��������I
	Bytes InstructionRegister;//ָ��Ĵ��������IR
	Bytes ProgramCounter;//��������������PC
	Bytes BasePointer;//��ַָ�룬���BP
	bool Carry;//��λ��־�������C
	bool Zero;//�������Ƿ�Ϊ0�����Ϊ0��Z=1
	bool Sign;//���ű�־�����Ϊ��ʱ��S=1
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
	/*
		!!!!ע�⣺B ������������ǰ���V ��������������  ����V����[B] ��B��ַ��Ԫ�е�����
	*/
	OpHALT,	//CPU��ָͣ�� ��ʽ��HALT
	OpCLEARAX,		//�ۼ�����0
	OpClEARC,	//��λ��־����0
	OpCLEARI,//��ַ�Ĵ�����0
	OpINAXD,	//��10������д���ۼ���
	OpINAXB,	//��2������д���ۼ���
	OpINAXA,	//��ascii�ַ�д���ۼ���
	OpOUTAXD,	//���ۼ���������10������ʽ���
	OpOUTAXB,	//���ۼ���������2������ʽ���
	OpOUTAXA,	//���ۼ���������ascii�ַ���ʽ���
	OpINCAX,//�ۼ�����1��Ӱ���־��
	OpDECAX,//�ۼ�����1��Ӱ���־��
	OpINCI,//��ַ�Ĵ�����1��Ӱ���־��
	OpDECI,//��ַ�Ĵ�����1��Ӱ���־��
	OpAXTOI,//�ۼ������������ַ�Ĵ��� x
	OpPUSH,//ѹջ����ջָ���1���ۼ���������ѹ��ջ����
	OpPOP,//��ջ����ջָ���1����ջ������ѹ��ջ��
	OpLOADBAX,//��ʽ LDA B ����B��ַ��Ԫ�е����������ۼ����У��Ե�ǰPC��ָ�ڴ����ֵ��Ϊ��ַƫ��
	OpLOADIBAX,//����ַ�Ĵ���+������B��ָ���ڴ浥Ԫ�����������ۼ��� A=[I+B]
	OpLOADVBAX,//��������B�����ۼ���
	OpLOADVBSP,//��������B�е������͵�SP�Ĵ���
	OpSTOREAXB,//[B]=A
	OpSIOREAXBI,//[B+I]=A
	//�ӷ�
	OpADDB,//A=A+[B]
	OpADDIB,//A=A+[I+B]
	OpADDVB,//A=A+B
	OpADCB,//A=A+C+[B]
	OpADCIB,//A=A+C+[I+B]
	OpADCVB,//A=A+C+B
	//����
	OpSUBB,//A=A-[B]
	OpSUBIB,//A=A-[I+B]
	OpSUBVB,//A=A-B
	OpSBCB,//A=A-C-[B]
	OpSBCIB,//A=A-C-[I+B]
	OpSBCVB,//A=A-C-B
	//�Ƚ�
	OpCMPB,//A��[B]���ݽ��бȽϣ�Ӱ���־λ
	OpCMPIB,//A��[B+I]���ݽ��бȽϣ�Ӱ���־λ
	OpCMPVP,//A��B�Ƚϣ�Ӱ���־λ
	//��
	OpANDB,//A��[B]������λ�룬Ӱ���־λ
	OpANDVB,//A��Bλ�룬Ӱ���־λ
	OpANDIB,//A��[I+B]λ�룬Ӱ���־λ
	//��
	OpORB,//A��[B]������λ��Ӱ���־λ
	OpORVB,//A��Bλ��Ӱ���־λ
	OpORIB,//A��[I+B]λ��Ӱ���־λ
	//��ת
	OpJMPB,//��ת��B��ַ
	OpJZB,//���Z��־Ϊ1����ת��B��Ԫ
	OpJNZB,//���Z��־Ϊ0����ת��B��Ԫ
	OpJSB,//���S��־Ϊ1����ת��B��Ԫ
	OpJNSB,//���S��־Ϊ0����ת��B��Ԫ
	OpJC,//���C��־Ϊ1����ת��B��Ԫ
	OpJNC,//���C��־Ϊ0����ת��B��Ԫ
};
//ָ�����Ƿ�
string OpMemonic[] =
{
	"HALT",	//CPU��ָͣ�� ��ʽ��HALT
	"CLEARAX",		//�ۼ�����0
	"ClEARC",	//��λ��־����0
	"CLEARI",//��ַ�Ĵ�����0
	"INAXD",	//��10������д���ۼ���
	"INAXB",	//��2������д���ۼ���
	"INAXA",	//��ascii�ַ�д���ۼ���
	"OUTAXD",	//���ۼ���������10������ʽ���
	"OUTAXB",	//���ۼ���������2������ʽ���
	"OUTAXA",	//���ۼ���������ascii�ַ���ʽ���
	"INCAX",//�ۼ�����1��Ӱ���־��
	"DECAX",//�ۼ�����1��Ӱ���־��
	"INCI",//��ַ�Ĵ�����1��Ӱ���־��
	"DECI",//��ַ�Ĵ�����1��Ӱ���־��
	"AXTOI",//�ۼ������������ַ�Ĵ��� x
	"PUSH",//ѹջ����ջָ���1���ۼ���������ѹ��ջ����
	"POP",//��ջ����ջָ���1����ջ������ѹ��ջ��
	"LOADBAX",//��ʽ LDA B ����B��ַ��Ԫ�е����������ۼ����У��Ե�ǰPC��ָ�ڴ����ֵ��Ϊ��ַƫ��
	"LOADIBAX",//����ַ�Ĵ���+������B��ָ���ڴ浥Ԫ�����������ۼ��� A=[I+B]
	"LOADVBAX",//��������B�����ۼ���
	"LOADVBSP",//��������B�е������͵�SP�Ĵ���
	"STOREAXB",//[B]=A
	"SIOREAXBI",//[B+I]=A
	//�ӷ�
	"ADDB",//A=A+[B]
	"ADDIB",//A=A+[I+B]
	"ADDVB",//A=A+B
	"ADCB",//A=A+C+[B]
	"ADCIB",//A=A+C+[I+B]
	"ADCVB",//A=A+C+B
	//����
	"SUBB",//A=A-[B]
	"SUBIB",//A=A-[I+B]
	"SUBVB",//A=A-B
	"SBCB",//A=A-C-[B]
	"SBCIB",//A=A-C-[I+B]
	"SBCVB",//A=A-C-B
	//�Ƚ�
	"CMPB",//A��[B]���ݽ��бȽϣ�Ӱ���־λ
	"CMPIB",//A��[B+I]���ݽ��бȽϣ�Ӱ���־λ
	"CMPVP",//A��B�Ƚϣ�Ӱ���־λ
	//��
	"ANDB",//A��[B]������λ�룬Ӱ���־λ
	"ANDVB",//A��Bλ�룬Ӱ���־λ
	"ANDIB",//A��[I+B]λ�룬Ӱ���־λ
	//��
	"ORB",//A��[B]������λ��Ӱ���־λ
	"ORVB",//A��Bλ��Ӱ���־λ
	"ORIB",//A��[I+B]λ��Ӱ���־λ
	//��ת
	"JMPB",//��ת��B��ַ
	"JZB",//���Z��־Ϊ1����ת��B��Ԫ
	"JNZB",//���Z��־Ϊ0����ת��B��Ԫ
	"JSB",//���S��־Ϊ1����ת��B��Ԫ
	"JNSB",//���S��־Ϊ0����ת��B��Ԫ
	"JC",//���C��־Ϊ1����ת��B��Ԫ
	"JNC",//���C��־Ϊ0����ת��B��Ԫ
};
#endif
