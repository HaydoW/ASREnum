using Microsoft.Win32;
using System;
using System.Collections.Generic;

namespace ASREnum
{
    internal class Program
    {
        static void Main(string[] args)
        {

            var rules = new List<KeyValuePair<string, string>>();
            rules.Add(new KeyValuePair<string, string>("Block abuse of exploited vulnerable signed drivers", "56a863a9-875e-4185-98a7-b882c64b5ce5"));
            rules.Add(new KeyValuePair<string, string>("Block Adobe Reader from creating child processes", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"));
            rules.Add(new KeyValuePair<string, string>("Block all Office applications from creating child processes", "d4f940ab-401b-4efc-aadc-ad5f3c50688a"));
            rules.Add(new KeyValuePair<string, string>("Block credential stealing from the Windows local securit authority subsystem (lsass.exe)", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"));
            rules.Add(new KeyValuePair<string, string>("Block executable content from email client and webmail", "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"));
            rules.Add(new KeyValuePair<string, string>("Block executable files from running unless they meet a prevalence, age, or trusted list criterion", "01443614-cd74-433a-b99e-2ecdc07bfc25"));
            rules.Add(new KeyValuePair<string, string>("Block execution of potentially obfuscated scripts", "5beb7efe-fd9a-4556-801d-275e5ffc04cc"));
            rules.Add(new KeyValuePair<string, string>("Block JavaScript or VBScript from launching downloaded executable content", "d3e037e1-3eb8-44c8-a917-57927947596d"));
            rules.Add(new KeyValuePair<string, string>("Block Office applications from creating executable content", "3b576869-a4ec-4529-8536-b80a7769e899"));
            rules.Add(new KeyValuePair<string, string>("Block Office applications from injecting code into other processes", "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"));
            rules.Add(new KeyValuePair<string, string>("Block Office communication application from creating child processes", "26190899-1602-49e8-8b27-eb1d0a1ce869"));
            rules.Add(new KeyValuePair<string, string>("Block persistence through WMI event subscription", "e6db77e5-3df2-4cf1-b95a-636979351e5b"));
            rules.Add(new KeyValuePair<string, string>("Block process creations originating from PSExec and WMI commands", "d1e49aac-8f56-4280-b9ba-993a6d77406c"));
            rules.Add(new KeyValuePair<string, string>("Block untrusted and unsigned processes that run from USB", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"));
            rules.Add(new KeyValuePair<string, string>("Block Win32 API calls from Office macros", "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"));
            rules.Add(new KeyValuePair<string, string>("Use advanced protection against ransomware", "c1db55ab-c21a-4637-bb3f-a12568109d35"));

            var explicitDisabled = new List<string>();
            var enabled = new List<string>();
            var audit = new List<string>();
            var warn = new List<string>();
            var implicitDisabled = new List<string>();

            RegistryKey localKey;
            if (Environment.Is64BitOperatingSystem)
            {
                localKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            }
            else
            {
                localKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            }

            foreach (var rule in rules)
            {
                try
                {
                    int value = (int)localKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules").GetValue(rule.Value);

                    switch (value)
                    {
                        case 0: // Disabled 
                            explicitDisabled.Add(rule.Key);   
                            break;
                        case 1: // Enabled
                            enabled.Add(rule.Key);
                            break;
                        case 2: // Audit
                            audit.Add(rule.Key);
                            break;
                        case 6: // Warn
                            warn.Add(rule.Key);
                            break;
                    }

                }
                catch (NullReferenceException nr)
                {
                    implicitDisabled.Add(rule.Key);
                }
            }

            localKey.Close();

            Console.WriteLine("\nRULES IN ENABLED MODE");
            Console.WriteLine("=====================");
            foreach (string rule in enabled)
            {
                Console.WriteLine(rule);
            }

            Console.WriteLine("\nRULES IN WARN MODE");
            Console.WriteLine("==================");
            foreach (string rule in warn)
            {
                Console.WriteLine(rule);
            }

            Console.WriteLine("\nRULES IN AUDIT MODE");
            Console.WriteLine("=========================");
            foreach (string rule in audit)
            {
                Console.WriteLine(rule);
            }

            Console.WriteLine("\nRULES IN DISABLED MODE (EXPLICIT)");
            Console.WriteLine("================================");
            foreach (string rule in explicitDisabled)
            {
                Console.WriteLine(rule);
            }

            Console.WriteLine("\nRULES IN DISABLED MODE (IMPLICIT)");
            Console.WriteLine("================================");
            foreach (string rule in implicitDisabled)
            {
                Console.WriteLine(rule);
            }
        }
    }
}
