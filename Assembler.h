#pragma once
#ifndef _ASSEMBLER_H
#define _ASSEMBLER_H
#include "Token.h"
#include "Lmachine.h"
#include "Global.h"
//�����
class Assembler
{
public:
	/*
	���ݳ�Ա
	*/
	Lmachine * lmachine;//�����ʵ��ָ��
	int TokenIndex;//token�Ǻ�����
	fstream *Code;//Ҫ���صĻ���ļ�
	vector<Token> LmachineToken; //�������ַ���
	vector<Symbol> SymbolTable;//���ű�̬����
	/*
	��Ա����
	*/
	Assembler();
	~Assembler();
	void Init(string codefilename);//��ʼ��
	TokenType Lexer(Token token, string &Strtoken, Operand &operand);//�������ַ�������
	void ReadLine();//��FILE����Code���ֶ�ȡ��LmachineToken��
	void Run_Assembler();	//���л����
	void BuildSymbolTable();//�������ű�
	int  SearchSymbol(string symbolname, int sign);//�ڷ��ű��в��ҷ���
	Bytes SearchCmd(Token token);//��ѯ���ָ������ض�Ӧ�Ļ���ָ�����ָ������Ϊָ��������±�
};
#endif