#include <iostream>
#include <iterator>
#include <map>
#include <vector>
#include <windows.h>

using namespace std;

int main()
{

    vector<wstring> explicitDisabled;
    vector<wstring> implicitDisabled;
    vector<wstring> enabled;
    vector<wstring> audit;
    vector<wstring> warn;

    map<wstring, wstring> rules;
    rules.insert(pair<wstring, wstring>(L"Block abuse of exploited vulnerable signed drivers", L"56a863a9-875e-4185-98a7-b882c64b5ce5"));
    rules.insert(pair<wstring, wstring>(L"Block Adobe Reader from creating child processes", L"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"));
    rules.insert(pair<wstring, wstring>(L"Block all Office applications from creating child processes", L"d4f940ab-401b-4efc-aadc-ad5f3c50688a"));
    rules.insert(pair<wstring, wstring>(L"Block credential stealing from the Windows local security authority subsystem (lsass.exe)", L"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"));
    rules.insert(pair<wstring, wstring>(L"Block executable content from email client and webmail", L"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"));
    rules.insert(pair<wstring, wstring>(L"Block executable files from running unless they meet a prevalence, age, or trusted list criterion", L"01443614-cd74-433a-b99e-2ecdc07bfc25"));
    rules.insert(pair<wstring, wstring>(L"Block execution of potentially obfuscated scripts", L"5beb7efe-fd9a-4556-801d-275e5ffc04cc"));
    rules.insert(pair<wstring, wstring>(L"Block JavaScript or VBScript from launching downloaded executable content", L"d3e037e1-3eb8-44c8-a917-57927947596d"));
    rules.insert(pair<wstring, wstring>(L"Block Office applications from creating executable content", L"3b576869-a4ec-4529-8536-b80a7769e899"));
    rules.insert(pair<wstring, wstring>(L"Block Office applications from injecting code into other processes", L"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"));
    rules.insert(pair<wstring, wstring>(L"Block Office communication application from creating child processes", L"26190899-1602-49e8-8b27-eb1d0a1ce869"));
    rules.insert(pair<wstring, wstring>(L"Block persistence through WMI event subscription", L"e6db77e5-3df2-4cf1-b95a-636979351e5b"));
    rules.insert(pair<wstring, wstring>(L"Block process creations originating from PSExec and WMI commands", L"d1e49aac-8f56-4280-b9ba-993a6d77406c"));
    rules.insert(pair<wstring, wstring>(L"Block untrusted and unsigned processes that run from USB", L"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"));
    rules.insert(pair<wstring, wstring>(L"Block Win32 API calls from Office macros", L"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"));
    rules.insert(pair<wstring, wstring>(L"Use advanced protection against ransomware", L"c1db55ab-c21a-4637-bb3f-a12568109d35"));

    HKEY hRegKey = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules", 0, KEY_READ, &hRegKey) == ERROR_SUCCESS) {

        map<wstring, wstring>::iterator itr;
        for (itr = rules.begin(); itr != rules.end(); itr++) {

            DWORD dwType = REG_DWORD;
            DWORD dwValue;
            DWORD dwBufSize = sizeof(DWORD);

            LSTATUS status = RegQueryValueExW(hRegKey, itr->second.c_str(), NULL, &dwType, (LPBYTE)&dwValue, &dwBufSize);

            if (status == ERROR_SUCCESS) {

                switch (dwValue) {
                case 0:
                    explicitDisabled.push_back(itr->first);
                    break;
                case 1:
                    enabled.push_back(itr->first);
                    break;
                case 2:
                    audit.push_back(itr->first);
                    break;
                case 6:
                    warn.push_back(itr->first);
                    break;
                }
            }
            else if (status == ERROR_FILE_NOT_FOUND)
            {
                implicitDisabled.push_back(itr->first);
            }
            else
            {
                wcout << "[+] An error occured while trying to read key: " << itr->second << endl;
            }
        }

        RegCloseKey(hRegKey);


        wcout << "\nRULES IN ENABLED MODE" << endl;
        wcout << "=====================" << endl;
        for (int i = 0; i < enabled.size(); i++) {
            wcout << enabled[i] << endl;
        }

        wcout << "\nRULES IN WARN MODE" << endl;
        wcout << "==================" << endl;
        for (int i = 0; i < warn.size(); i++) {
            wcout << warn[i] << endl;
        }

        wcout << "\nRULES IN AUDIT MODE" << endl;
        wcout << "===================" << endl;
        for (int i = 0; i < audit.size(); i++) {
            wcout << audit[i] << endl;
        }

        wcout << "\nRULES IN DISABLED MODE (EXPLICIT)" << endl;
        wcout << "=================================" << endl;
        for (int i = 0; i < explicitDisabled.size(); i++) {
            wcout << explicitDisabled[i] << endl;
        }

        wcout << "\nRULES IN DISABLED MODE (IMPLICIT)" << endl;
        wcout << "=================================" << endl;
        for (int i = 0; i < implicitDisabled.size(); i++) {
            wcout << implicitDisabled[i] << endl;
        }

    }
    else
    {
        wcout << "[!] Could not enumerate ASR Rules!" << endl;
    }
}
