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
void Lmachine::LmachineRun()
{
	Bytes Carry;//�����λλ��״̬
	cpu.Psw1 = false;
	cpu.Psw2 = false;
	cpu.Psw3 = false;
	cpu.Accumulator = 0;
	cpu.IndexRegister = 0;
	cpu.BasePointer = 0;
	cpu.StackPointer = 0;
	cpu.ProgramCounter = 0;
	CPUStatus = Running;
	do
	{
		cpu.InstructionRegister = Memory[cpu.ProgramCounter];

	}
}
//������
int main()
{
	Lmachine *lmachine=new Lmachine;
	lmachine->Init();
	Assembler * assembler = new Assembler;


}