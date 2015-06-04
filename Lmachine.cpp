#include <iostream>
#include <fstream>
#include "Lmachine.h"
#include "Assembler.h"
using namespace std;
/*
--------------------------------------------------------------
|						�����                               |
--------------------------------------------------------------
*/

//��ʼ��
void Lmachine::Init()
{
	
	/*
		��ʼ��
	*/

}
//ִ�м�1����
void Lmachine::Increment(Bytes & data)
{
	data = (data + 257) % 256;
}
//ִ�м�1����
void Lmachine::Decrement(Bytes & data)
{
	data = (data + 255) % 256;
}
void Lmachine::LmachineRun()
{
	Bytes ProgramValue;//����PC�ĵ�ǰֵ
	Bytes Carry;//�����λλ��״̬
	Lcpu.Carry = false;

	Lcpu.Accumulator = 0;
	Lcpu.IndexRegister = 0;
	Lcpu.BasePointer = 0;
	Lcpu.StackPointer = 0;
	Lcpu.ProgramCounter = 0;
	LcpuStatus = Running;
	do
	{
		Lcpu.InstructionRegister = Memory[Lcpu.ProgramCounter];//���ڴ���ȡָ������ָ��Ĵ���
		ProgramValue = Lcpu.ProgramCounter;
		Increment(Lcpu.ProgramCounter);//PCָ����һ����Ҫִ�е�ָ���ַ
		switch (Lcpu.InstructionRegister)
		{
		case OpHALT:	//CPU��ָͣ�� ��ʽ��HALT
			LcpuStatus = Finished;
			break;
		case OpCLEARAX:	//�ۼ�����0
			Lcpu.Accumulator = 0;
			break;
		case OpClEARC:	//��λ��־����0
			Lcpu.Carry = 0;
			break;
		case OpCLEARI://��ַ�Ĵ�����0
			Lcpu.IndexRegister = 0;
			break;
		case OpINAXD:	//��10������д���ۼ���
		case OpINAXB:	//��2������д���ۼ���
		case OpINAXA:	//��ascii�ַ�д���ۼ���
		case OpOUTAXD:	//���ۼ���������10������ʽ���
		case OpOUTAXB:	//���ۼ���������2������ʽ���
		case OpOUTAXA:	//���ۼ���������ascii�ַ���ʽ���

		case OpINCAX://�ۼ�����1��Ӱ���־��
			Increment(Lcpu.Accumulator);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpDECAX://�ۼ�����1��Ӱ���־��
			Decrement(Lcpu.Accumulator);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpINCI://��ַ�Ĵ�����1��Ӱ���־��
			Increment(Lcpu.IndexRegister);
			SetFlags(Lcpu.IndexRegister);
			break;
		case OpDECI://��ַ�Ĵ�����1��Ӱ���־��
			Decrement(Lcpu.IndexRegister);
			SetFlags(Lcpu.IndexRegister);
			break;
		case OpAXTOI://�ۼ������������ַ�Ĵ��� x
			Lcpu.IndexRegister = Lcpu.Accumulator;
			break;
		case OpPUSH://ѹջ����ջָ���1���ۼ���������ѹ��ջ����
			Decrement(Lcpu.StackPointer);
			Memory[Lcpu.StackPointer] = Lcpu.Accumulator;
			break;
		case OpPOP://��ջ����ջָ���1����ջ������ѹ��ջ��
			Lcpu.Accumulator = Memory[Lcpu.StackPointer];
			Increment(Lcpu.StackPointer);
			Memory[Lcpu.StackPointer] = Lcpu.Accumulator;
			break;
		case OpLOADBAX://��ʽ LDA B ����B��ַ��Ԫ�е����������ۼ����У��Ե�ǰPC��ָ�ڴ����ֵ��Ϊ��ַƫ��
			Lcpu.Accumulator = Memory[Memory[Lcpu.ProgramCounter]];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
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
		default:
			break;
		}
	}
}
//������
int main()
{
	Lmachine *lmachine=new Lmachine;
	lmachine->Init();
	Assembler * assembler = new Assembler;


}