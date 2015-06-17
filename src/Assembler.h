#pragma once
#include "Token.h"
#include "Global.h"
using namespace std;
class Lmachine;
//�����
class Assembler
{
public:
	/*
	���ݳ�Ա
	*/
	Lmachine * lmachine;
	string CodeName;//�����ļ�����
	size_t TokenIndex;//token�Ǻ�����
	vector<Token> LmachineToken; //�������ַ���
	vector<Symbol> SymbolTable;//���ű�̬����
	/*
	��Ա����
	*/
	Assembler();
	~Assembler();
	void Init(string codefilename, Lmachine * &lmachine);//��ʼ��
	TokenType Lexer(Token token, string &Strtoken);//�������ַ�������
	void ReadLine();//��FILE����Code���ֶ�ȡ��LmachineToken��
	void Run_Assembler();	//���л����
	void BuildSymbolTable();//�������ű�
	int  SearchSymbol(string symbolname, int sign);//�ڷ��ű��в��ҷ���
	Bytes SearchCmd(Token token);//��ѯ���ָ������ض�Ӧ�Ļ���ָ�����ָ������Ϊָ��������±�
};