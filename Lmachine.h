#pragma once
#ifndef _LMACHINE_H
#define _LMACHINE_H
#include "Global.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
using namespace std;

//�����
class Lmachine
{
public:
	/*
		���ݳ�Ա
	*/
	ostream fout;//����ļ�����
	string OutFileName;//������ļ���
	string CodeFileName;//��Ҫ�򿪵Ĵ����ļ���
	CPU Lcpu;//�������CPU
	Status LcpuStatus;//�����CPU������״̬
	Bytes Memory[MemSize];//������ڴ�ռ�
	LmachineError LError;//���������
	LmachineEndStatus LendStatus;//���������ʱ��״̬
	/*
		��Ա����
	*/
	Lmachine();//Ĭ���޲ι��캯��
	void Init();//��ʼ�����Լ���ʼ��ӭ���� ���û�ѡ������
	string GetMemonic(int i); //���ػ���ָ��i�����Ƿ���Ҳ���ǻ��ָ��
	void LmachineRun();//ִ�г���
	void LmachineAPI();//����������ƺ���
	void Increment(Bytes &data);//ִ�м�1����
	void Decrement(Bytes &data);//ִ�м�1����
	void SetFlags(Bytes Register);//���ݼĴ�����ֵ�趨��־��
	void PrintRunError();//����������еĴ���
	Bytes Index();//�����ַ��ַ AX+B
	Bytes Opcode(string token);//ȡ��string����token����Ӧ�Ļ���ָ��
	void LmachineQuit();//�˳������
};

#endif
