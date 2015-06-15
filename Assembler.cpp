#include "Assembler.h"
#include "Lmachine.h"
#include "boost/regex.hpp"
using namespace std;
/*
--------------------------------------------------------------
|						�����                               |
--------------------------------------------------------------
*/
Assembler::Assembler()
{
	Lmachine * lmachine = new Lmachine;
}
//�������ʼ��
void Assembler::Init(string codefilename,Lmachine *& Reflmachine)
{
	TokenIndex = 0;//��Token�Ǻų�ʼ��Ϊ0
    Code->open(lmachine->String2Char(codefilename));//�򿪵�ָ���Ļ������ļ�
	ReadLine();//��FILE����Code���ֶ�ȡ��LmachineToken��
	lmachine = Reflmachine;
}
//���л����
void Assembler::Run_Assembler()
{
	int labelindex, number;
	Bytes lc = 0;//��ַ������
	Bytes Op;
	string Strtoken;
	TokenType type;
	BuildSymbolTable();//��һ��ɨ�� �������ű�
	/*
		��2��ɨ�裬�����ݷ��ű���Դ����д��Memory��
	*/
	for (size_t i = 0; i < LmachineToken.size(); i++)
	{
		type = Lexer(LmachineToken[i], Strtoken);
		switch (type)
		{
		case ASMCode://���ָ��
			Op = lmachine->Opcode(Strtoken); //��ѯ���ָ�����Ļ���ָ��
			if (Op == OpError) //����ָ��򲻴��ڵ�ָ��
			{
				cout << "error mnemonic " << Strtoken << endl;
			}
			lmachine->Memory[lc] = Op; //�洢ָ���������ڴ���
			lc = (lc + 1) % MemSize;//��ַ������1
			break;
		case ReferLabel://�Ե�ַ��ŵ�����
			Strtoken += ":";
			labelindex = SearchSymbol(Strtoken, 1); //�ڷ��ű���Ѱ���һ�ȡ��ŵ��±�
			if (labelindex == -1)//������
			{
				cout << "Error: no such a lable" << Strtoken << endl;
			}
			else
			{
				lmachine->Memory[lc] = SymbolTable[labelindex].SymbolAddr;
				lc = (lc + 1) % MemSize;
			}
		case Number:
			number = LmachineToken[i].GetNumber();
			if (number > 0)
				lmachine->Memory[lc] = number % 256;
			else
				lmachine->Memory[lc] = (256 - abs(number) % 256) % 256;
			lc = (lc + 1) % 256;

		default:
			break;
		}

	}
}
//�������ַ�������
TokenType Assembler::Lexer(Token token, string &Strtoken)
{
	TokenType type;
	Bytes command;
	if (isalpha(token.GetID()[0])) //�ǵ�ַ��Ż���ָ��
	{
		command = SearchCmd(token);
		if (command == MaxInstuction&&LmachineToken[TokenIndex + 1].GetID() == ":")
		{
			type = Lablel;//ȷ��Ϊ��ַ��ŵĶ���
			Strtoken = token.GetID() + LmachineToken[TokenIndex + 1].GetID();
		}
		else if (command == MaxInstuction&&LmachineToken[TokenIndex + 1].GetID() != ":")
		{
			type = ReferLabel;//ȷ���Ե�ַ��ŵ�����
			Strtoken = token.GetID();
		}
		else
			type = ASMCode;//ȷ��Ϊ���ָ��

	}
	else if (isdigit(token.GetID()[0]))
	{
		if (token.IsID)
			type = Number;
	}
	else
		type = UnKnown;
	return type;
}
//��FILE����Code���ֶ�ȡ��LmachineToken��
void Assembler::ReadLine()
{
	string Line;
	while (getline(*Code, Line)) //ÿ�ж�ȡ������
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
					LmachineToken.push_back(token);
					if ((Line.length() - tokentext.length() - 1) == 0)
						break;
					Line = Line.substr((Line.length() - tokentext.length() - 1));
				}
				else if (what[3].matched == true) //ID
				{
					string tokentext(what[3].first, what[3].second);
					Token token(tokentext);
					LmachineToken.push_back(token);
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
//�ڷ��ű��в��ҷ���,sign=0,�ж��Ƿ�������ظ����壬sign=1,�Ƿ��Ѿ��и÷��ţ����и���
int Assembler::SearchSymbol(string symbolname, int sign)
{
	size_t i;
	for ( i= 0; i < SymbolTable.size(); i++)
	{
		if (symbolname == SymbolTable[i].SymbolName) //�ڷ��ű����ҵ��÷���
			break;
	}
	if (i < SymbolTable.size() && sign == 0)
	{
		cout << "the label" << symbolname << "is already defined" << endl;
		return -2;//����ظ�����
	}
	else if (i < SymbolTable.size() && sign == 1)
		return i;//���ر���ڷ��ű��е��±꣬���ڸ���
	else
		return -1;//���Ų�����
}
//������ű�
void Assembler::BuildSymbolTable()
{
	int labelindex;
	TokenType type;
	string Strtoken;
	for (TokenIndex = 0; TokenIndex < LmachineToken.size(); TokenIndex++)
	{
		type = Lexer(LmachineToken[TokenIndex], Strtoken);
		switch (type)
		{
		case Lablel:	//�¶����ţ�������ű�
			if (SearchSymbol(LmachineToken[TokenIndex].GetID(), 0) == -1)//���Ų�����
			{
				Symbol symbol;
				symbol.SymbolName = Strtoken;
				symbol.SymbolAddr = type - SymbolTable.size();
				symbol.First = NULL;
			}
			break;
		case ReferLabel://��ŵ�ַ�����ã����Ѵ��ڣ�����
			Strtoken += ":";
			labelindex = SearchSymbol(Strtoken, 1);
			if (labelindex == -1) //���ű�����
				cout << "the label" << Strtoken << "is not defined" << endl;//��ʾ�����ˣ����ǲ�δ����
			else
			{
				SymbolReferenceNode *newnode = new SymbolReferenceNode;
				newnode->ReferenceAddr = type - 1;
				newnode->Next = NULL;
				if (SymbolTable[labelindex].First = NULL)
					SymbolTable[labelindex].First = newnode;
				else
				{
					SymbolReferenceNode * refer = SymbolTable[labelindex].First;
					SymbolReferenceNode * refernode = refer;
					while (refer != NULL)
					{
						refernode = refer;
						refer = refer->Next;
					}
					refernode->Next = newnode;
				}
			}
			break;
		case UnKnown:	//����ʶ��ķ���
			cout << "the label" << Strtoken << "is Unknown" << endl;
			break;
		default:
			break;
		}
	}
}
//��ѯ���ָ������ض�Ӧ�Ļ���ָ�����ָ������Ϊָ��������±�
Bytes Assembler::SearchCmd(Token token)
{
	int i = 0;
	while (i < MaxInstuction && (lmachine->GetMemonic(i) == token.GetID()))
		i++;
	return (Bytes)i;
}

