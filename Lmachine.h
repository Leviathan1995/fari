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
	CPU Lcpu;//�������CPU
	Status LcpuStatus;//�����CPU������״̬
	Bytes Memory[MemSize];//������ڴ�ռ�

	/*
		��Ա����
	*/
	void Init();//��ʼ��
	inline string GetMemonic(int i) //���ػ���ָ��i�����Ƿ�
	{
		return  OpMemonic[i];
	}
	void LmachineRun();//ִ�г���
	void Increment(Bytes &data);//ִ�м�1����
	void Decrement(Bytes &data);//ִ�м�1����
	void SetFlags(Bytes Register);//���ݼĴ�����ֵ�趨��־��
	void PrintRunError();//����������еĴ���
	Bytes Index();//�����ַ��ַ AX+B

};

#endif
