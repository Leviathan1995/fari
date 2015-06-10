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
	string Judge;
	/*
		��ʼ��
	*/
	cout << "--------------------------------------" << endl;
	cout << "|         welcome to Lmachine        |" << endl;
	cout << "|                                    |" << endl;
	cout << "|                                    |" << endl;
	cout << "|                    By: Leviathan   |" << endl;
	cout << "--------------------------------------" << endl;
	cout << "�����������ļ���          " << endl;
	cout << "					:    " << endl;
	cin >>CodeFileName;
	cout << "����������ļ���          " << endl;
	cout << "					:    " << endl;
	cin >> OutFileName;
	cout << "�Ƿ�ִ�� y/n ��" << endl;
	cin >> Judge;
	while (Judge != "y" || Judge != "Y" || Judge != "n" || Judge != "N")
	{
		cout << "��������ȷ��ָ��" << endl;
		cin >> Judge;
	}
	if (Judge == "y" || Judge == "Y")
		LmachineAPI();//����������Ƴ���
	else if (Judge == "n" || Judge == "N")
		LmachineQuit();//�˳������
	ofstream fout(OutFileName); //�½�����ļ�
	if (fout)
		cout << OutFileName << "�ļ��½��ɹ�" << endl;
}
//����������ƺ���
void Lmachine::LmachineAPI()
{
	Assembler *assembler = new Assembler;
	assembler->Init(CodeFileName);//�������ʼ�������ݴ����ļ���
	assembler->Run_Assembler();//���л����
	LmachineRun();//���������
}
//�趨��־�Ĵ���
void Lmachine::SetFlags(Bytes Register)
{
	Lcpu.Zero = (Register == 0);
	Lcpu.ProgramCounter = (Register <= 127);
}
//ȡ��string����token����Ӧ�Ļ���ָ��
Bytes Lmachine::Opcode(string token)
{
	Bytes Op = OpHALT;
	while (Op < MaxInstuction&&token != OpMemonic[Op])
		Op++;
	if (Op < MaxInstuction)
		return Op;
	else
		return OpError;//���ش���ָ��Ĵ���
}
//�����ַ��ַ X+B
Bytes Lmachine::Index()
{
	return ((Memory[Lcpu.ProgramCounter] + Lcpu.Accumulator) % 256);
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
//�����ִ���ڴ��еĻ��ָ��
void Lmachine::LmachineRun()
{
	Bytes ProgramValue;//����PC�ĵ�ǰֵ
	Bytes Carry;//�����λλ��״̬
	Lcpu.Carry = false;
	Lcpu.Zero = false;
	Lcpu.Sign = false;
	Lcpu.Accumulator = 0;
	Lcpu.IndexRegister = 0;
	Lcpu.BasePointer = 0;
	Lcpu.StackPointer = 0;
	Lcpu.ProgramCounter = 0;//����ʼλ��
	LcpuStatus = Running;//CPU����״̬
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
			if (Lcpu.Accumulator<128)
				fprintf
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
		case OpLOADIBAX://����ַ�Ĵ���+������B��ָ���ڴ浥Ԫ�����������ۼ��� A=[I+B]
			Lcpu.Accumulator = Memory[Index()];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpLOADVBAX://��������B�����ۼ���
			Lcpu.Accumulator = Memory[Lcpu.ProgramCounter];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpLOADVBSP://��������B�е������͵�SP�Ĵ���
			Lcpu.StackPointer = Memory[Memory[Lcpu.ProgramCounter]];
			Increment(Lcpu.ProgramCounter);
			break;
		case OpSTOREAXB://[B]=A
			Memory[Memory[Lcpu.ProgramCounter]] = Lcpu.Accumulator;
			Increment(Lcpu.ProgramCounter);
			break;
		case OpSIOREAXBI://[B+I]=A
			Memory[Index()] = Lcpu.Accumulator;
			Increment(Lcpu.Accumulator);
			break;
				//�ӷ�
		case OpADDB://A=A+[B]
			Lcpu.Carry = (Lcpu.Accumulator + Memory[Lcpu.ProgramCounter] > 255); //�Ƿ��λ
			Lcpu.Accumulator = (Lcpu.Accumulator + Memory[Memory[Lcpu.ProgramCounter]]) % 256;//�޶���ֵ�Ĵ�С
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpADDIB://A=A+[I+B]
			Lcpu.Carry = (Lcpu.Accumulator + Memory[Index()] > 255); //�Ƿ��λ
			Lcpu.Accumulator = (Lcpu.Accumulator + Memory[Index()]) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpADDVB://A=A+B
			Lcpu.Carry = (Lcpu.Accumulator + Memory[Lcpu.ProgramCounter]) > 255;
			Lcpu.Accumulator = (Lcpu.Accumulator + Memory[Lcpu.ProgramCounter]) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpADCB://A=A+C+[B] ����λλ
			Carry = Lcpu.Carry;
			Lcpu.Carry = (Lcpu.Accumulator + Memory[Memory[Lcpu.ProgramCounter]] + Carry) > 255;
			Lcpu.Accumulator = (Lcpu.Accumulator + Memory[Memory[Lcpu.ProgramCounter]] + Carry) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpADCIB://A=A+C+[I+B]
			Carry = Lcpu.Carry;
			Lcpu.Carry = (Lcpu.Accumulator + Memory[Index()] + Carry) > 255;
			Lcpu.Accumulator = (Lcpu.Accumulator + Memory[Index()] + Carry) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpADCVB://A=A+C+B
			Carry = Lcpu.Carry;
			Lcpu.Carry = (Lcpu.Accumulator + Memory[Lcpu.ProgramCounter] + Carry) > 255;
			Lcpu.Accumulator = (Lcpu.Accumulator + Memory[Lcpu.ProgramCounter] + Carry) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
				//����
		case OpSUBB://A=A-[B]
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Memory[Lcpu.ProgramCounter]]);
			Lcpu.Accumulator = (Lcpu.Accumulator - Memory[Memory[Lcpu.ProgramCounter]] + 256) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpSUBIB://A=A-[I+B]
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Index()]);
			Lcpu.Accumulator = (Lcpu.Accumulator - Memory[Index()] + 256) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpSUBVB://A=A-B
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Lcpu.ProgramCounter]);
			Lcpu.Accumulator = (Lcpu.Accumulator - Memory[Lcpu.ProgramCounter] + 256) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpSBCB://A=A-C-[B]
			Carry = Lcpu.Carry;
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Memory[Lcpu.ProgramCounter]] + Carry);
			Lcpu.Accumulator = (Lcpu.Accumulator - Carry - Memory[Memory[Lcpu.ProgramCounter]] + 256) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpSBCIB://A=A-C-[I+B]
			Carry = Lcpu.Carry;
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Index()] + Carry);
			Lcpu.Accumulator = (Lcpu.Accumulator - Carry - Memory[Index()] + 256) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpSBCVB://A=A-C-B
			Carry = Lcpu.Carry;
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Lcpu.ProgramCounter] + Carry);
			Lcpu.Accumulator = (Lcpu.Accumulator - Carry - Memory[Lcpu.ProgramCounter] + 256) % 256;
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
				//�Ƚ�
		case OpCMPB://A��[B]���ݽ��бȽϣ�Ӱ���־λ
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Memory[Lcpu.ProgramCounter]]);
			SetFlags((Lcpu.Accumulator - Memory[Memory[Lcpu.ProgramCounter]] + 256) % 256);
			Increment(Lcpu.ProgramCounter);
			break;
		case OpCMPIB://A��[B+I]���ݽ��бȽϣ�Ӱ���־λ
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Index()]);
			SetFlags((Lcpu.Accumulator - Memory[Index()] + 256) % 256);
			break;
		case OpCMPVB://A��B�Ƚϣ�Ӱ���־λ
			Lcpu.Carry = (Lcpu.Accumulator < Memory[Lcpu.ProgramCounter]);
			SetFlags((Lcpu.Accumulator - Memory[Lcpu.ProgramCounter] + 256) % 256);
			break;
				//��
		case OpANDB://A��[B]������λ�룬Ӱ���־λ
			Lcpu.Accumulator = Lcpu.Accumulator & Memory[Memory[Lcpu.ProgramCounter]];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			Lcpu.Carry = false;
			break;
		case OpANDVB://A��Bλ�룬Ӱ���־λ
			Lcpu.Accumulator = Lcpu.Accumulator & Memory[Lcpu.ProgramCounter];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			Lcpu.Carry = false;
			break;
		case OpANDIB://A��[I+B]λ�룬Ӱ���־λ
			Lcpu.Accumulator = Lcpu.Accumulator & Memory[Index()];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			Lcpu.Carry = false;
			break;
				//��
		case OpORB://A��[B]������λ��Ӱ���־λ
			Lcpu.Accumulator = Lcpu.Accumulator | Memory[Memory[Lcpu.ProgramCounter]];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpORVB://A��Bλ��Ӱ���־λ
			Lcpu.Accumulator = Lcpu.Accumulator | Memory[Lcpu.ProgramCounter];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
		case OpORIB://A��[I+B]λ��Ӱ���־λ
			Lcpu.Accumulator = Lcpu.Accumulator | Memory[Index()];
			Increment(Lcpu.ProgramCounter);
			SetFlags(Lcpu.Accumulator);
			break;
				//��ת
		case OpJMPB://��ת��B��ַ
			Lcpu.ProgramCounter = Memory[Lcpu.ProgramCounter];
			break;
		case OpJZB://���Z��־Ϊ1����ת��B��Ԫ
			if (Lcpu.Zero==1)
				Lcpu.ProgramCounter = Memory[Lcpu.ProgramCounter];
			else
				Increment(Lcpu.ProgramCounter);
			break;
		case OpJNZB://���Z��־Ϊ0����ת��B��Ԫ
			if (Lcpu.Zero == 0)
				Lcpu.ProgramCounter = Memory[Lcpu.ProgramCounter];
			else
				Increment(Lcpu.ProgramCounter);
			break;
		case OpJSB://���S��־Ϊ1����ת��B��Ԫ
			if (Lcpu.Sign == 1)
				Lcpu.ProgramCounter = Memory[Lcpu.ProgramCounter];
			else
				Increment(Lcpu.ProgramCounter);
			break;
		case OpJNSB://���S��־Ϊ0����ת��B��Ԫ
			if (Lcpu.Sign ==0)
				Lcpu.ProgramCounter = Memory[Lcpu.ProgramCounter];
			else
				Increment(Lcpu.ProgramCounter);
			break;
		case OpJC://���C��־Ϊ1����ת��B��Ԫ
			if (Lcpu.Carry == 1)
				Lcpu.ProgramCounter = Memory[Lcpu.ProgramCounter];
			else
				Increment(Lcpu.ProgramCounter);
			break;
		case OpJNC://���C��־Ϊ0����ת��B��Ԫ
			if (Lcpu.Carry == 1)
				Lcpu.ProgramCounter = Memory[Lcpu.ProgramCounter];
			else
				Increment(Lcpu.ProgramCounter);
			break;
	default:
			break;
		}
	}while (LcpuStatus == Running);
	if (LcpuStatus==Finished)

}
//���ػ���ָ��i�����Ƿ�,Ҳ���ǻ��ָ��
string Lmachine::GetMemonic(int i)
{
		return  OpMemonic[i];
}
//������
int main()
{
	Lmachine *lmachine=new Lmachine;
	lmachine->Init();
}