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
	cpu.Carry = false;

	cpu.Accumulator = 0;
	cpu.IndexRegister = 0;
	cpu.BasePointer = 0;
	cpu.StackPointer = 0;
	cpu.ProgramCounter = 0;
	CPUStatus = Running;
	do
	{
		cpu.InstructionRegister = Memory[cpu.ProgramCounter];//���ڴ���ȡָ������ָ��Ĵ���
		ProgramValue = cpu.ProgramCounter;
		Increment(cpu.ProgramCounter);//PCָ����һ����Ҫִ�е�ָ���ַ
		switch (cpu.InstructionRegister)
		{
		case OpCLEARACC://CPU�ۼ�����0
			cpu.Accumulator = 0;
			break;
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