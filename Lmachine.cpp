#include <iostream>
#include <boost/regex.hpp>
#include <fstream>
#include "Lmachine.h"
using namespace std;
//��ʼ��
void Lmachine::Init()
{
	/*
		�򿪵�ָ���Ļ������ļ�
	*/
	Code.open("code.txt");
	/*
		��ʼ��
	*/
	PC = 0;
	Data[0] = Data_SIZE - 1;
	for (int i = 1; i < Data_SIZE; i++) //���������
		Data[i] = 0;
	for (int i = 0; i < Operand_SIZE; i++)//��ʼ��ֻ��ָ��洢��
	{
		OperandMem[i].op = OpHLT;
		OperandMem[i].data1 = 0;
		OperandMem[i].data2 = 0;
		OperandMem[i].data3 = 0;
	}
	for (int i = 0; i = RegisterNum; i++)//��ռĴ���
		Register[i] = 0;
}
//��Codeһ��һ�ж�ȡ��LmachineToken������
void Lmachine::ReadLine()
{
	string Line;
	while (getline(Code, Line)) //ÿ�ж�ȡ������
	{
		if (boost::regex_search(Line, what, Regex))
		{
			while (what[0].length() != 0)
			{
				if (what[2].matched == true) //number
				{
					string tokentext(what[2].first, what[2].second);
					int tokennumber = atoi(tokentext.c_str());
					Token token(tokennumber);
					LmachineToken.push(token);
					if ((Line.length() - tokentext.length() - 1) == 0)
						break;
					Line = Line.substr((Line.length() - tokentext.length() - 1));
				}
				else if (what[3].matched == true) //ID
				{
					string tokentext(what[3].first, what[3].second);
					Token token(tokentext);
					LmachineToken.push(token);
					if ((Line.length() - tokentext.length() - 1) == 0)
						break;
					Line = Line.substr((Line.length() - tokentext.length() - 1));
				}
				if (boost::regex_search(Line, what, Regex))
				{
					continue;
				}
			}
		}
	}
}
int Lmachine::OpClass(int c)
{
	if (c <= OpRRMODE)
		return OperandRR;
	else if (c <= OpRMMODE)
		return OperandRM;
	else
		return OperandRA;
}
//��ָ����ص�ֻ��ָ��洢��
void Lmachine::Load()
{
	while (!LmachineToken.empty())
	{
		OperandMem[PC].op = Token2Op(LmachineToken.front());
	}
}