#include "Lmachine.h"
#include "Assembler.h"

using namespace std;

//������
int main()
{
	Lmachine *lmachine = new Lmachine;
	Assembler *assembler = new Assembler;
	if (lmachine->Init())//�ж��������ʼ���Ƿ�ɹ�
	{
		assembler->Init(lmachine->CodeFileName, lmachine);
		assembler->Run_Assembler();
		lmachine->LmachineRun();
	}
	else //���ɹ�
		return 0;
}