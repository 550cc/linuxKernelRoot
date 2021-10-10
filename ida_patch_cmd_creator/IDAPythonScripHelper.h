#ifndef IDA_PYTHON_SCRIPT_HELPER_H_
#define IDA_PYTHON_SCRIPT_HELPER_H_
#include <string>
#include <windows.h>
#include <fstream>
#include <sstream>


inline std::string& replace_all_distinct(std::string& str, const std::string& old_value, const std::string& new_value)
{
	for (std::string::size_type pos(0); pos != std::string::npos; pos += new_value.length())
	{
		if ((pos = str.find(old_value, pos)) != std::string::npos)
		{
			str.replace(pos, old_value.length(), new_value);
		}
		else
		{
			break;
		}
	}
	return str;
}


std::string GetFormatAsmBytes(const std::string & strAsmBytesLine)
{
	if (strAsmBytesLine.length() % 2)
	{
		return std::string();
	}

	std::stringstream ssFormatBytesTxt;
	int n = 0;
	for (size_t i = 0; i < strAsmBytesLine.length(); i++)
	{
		ssFormatBytesTxt << strAsmBytesLine[i];
		n++;
		if (n == 2 && i != strAsmBytesLine.length() - 1)
		{
			ssFormatBytesTxt << " ";
			n = 0;
		}
	}
	return ssFormatBytesTxt.str();
}


std::string GetIdaAsmScript(const std::string & strBytes, size_t writeAddr)
{
	std::string formatBytes = GetFormatAsmBytes(strBytes);
	std::stringstream ssScript;
	ssScript
		<< "buf = [0x" << replace_all_distinct(formatBytes, " ", ", 0x") << "]" << std::endl
		<< "for index in range(len(buf)) :" << std::endl
		<< "\t" << "patch_byte(0x" << std::hex << writeAddr << " + index, buf[index]);";
	return ssScript.str();
}

#endif /* IDA_PYTHON_SCRIPT_HELPER_H_ */
