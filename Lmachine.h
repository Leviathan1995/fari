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
	CPU cpu;//�������CPU
	Status CPUStatus;//�����CPU������״̬
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

};

#endif
