using System;
using System.Collections.Generic;
using System.IO;

namespace downgradeElf
{
    /// <summary>
    /// Argparse makes it easy to write user-friendly command-line interfaces.
    /// </summary>
    public class Argparse
    {
        public enum ActionEnum
        {
            None,
            Count,
            StoreTrue,
            StoreFalse,
        }
        public struct Argument
        {
            public string Name;
            public string Flag;
            public string Dest;
            public string Default;
            public bool Required;
            public bool IsNum;
            public string Value;
            public ActionEnum Action;

            public Argument(string name, string flag, string dest, string default_ = null, bool required = false, bool isNum = false, ActionEnum action = ActionEnum.None)
            {
                Name = name;
                Flag = flag;
                Dest = dest;
                IsNum = isNum;
                Default = default_;
                Required = required;
                Value = default_ == null ? "" : default_;
                Action = action;
            }
        }

        int nameMaxLen, dashMaxLen, flagMaxLen;
        public string Description { get; set; }
        public string Usage { get; set; }
        public List<string> DashFlags { get; private set; }
        public List<string> DashNames { get; private set; }
        public List<string> Names { get; private set; }
        public List<Argument> ArgDashs { get; private set; }
        public List<Argument> Args { get; private set; }
        public Dictionary<string, Argument> Arguments()
        {
            var dict = new Dictionary<string, Argument>();
            foreach (var arg in ArgDashs)
            {
                if (arg.Required && arg.Value.Length == 0) Error("the following arguments are required: " + arg.Name);
                dict.Add(arg.Name, arg);
            }
            foreach (var arg in Args)
            {
                if (arg.Required && arg.Value.Length == 0) Error("the following arguments are required: " + arg.Name);
                dict.Add(arg.Name, arg);
            }

            return dict;
        }

        /// <summary>
        /// Argparse makes it easy to write user-friendly command-line interfaces.
        /// </summary>
        /// <param name="description">describe this program</param>
        /// <param name="usage">custom usage, automatically generated if not specified</param>
        public Argparse(string description = "", string usage = "")
        {
            nameMaxLen = 0;
            dashMaxLen = 0;
            flagMaxLen = 0;
            Description = description;
            Usage = usage;
            DashFlags = new List<string>();
            DashNames = new List<string>();
            Names = new List<string>();
            ArgDashs = new List<Argument>();
            Args = new List<Argument>();
        }

        public void Add(string nameOrFlag, string dest) => Add(nameOrFlag, dest, null);
        public void Add(string nameOrFlag, string dest, string default_) => Add(nameOrFlag, dest, default_, false, false);
        public void Add(string nameOrFlag, string dest, string default_, bool required, bool isNum) => Add(nameOrFlag, dest, required, isNum, ActionEnum.None, default_);

        public void Add(string nameOrFlag, string dest, bool required) => Add(nameOrFlag, dest, required, false);
        public void Add(string nameOrFlag, string dest, bool required, bool isNum) => Add(nameOrFlag, dest, required, isNum, ActionEnum.None, null);

        public void Add(string nameOrFlag, string dest, bool required, string default_) => Add(nameOrFlag, dest, required, false, ActionEnum.None, default_);

        public void Add(string nameOrFlag, string dest, ActionEnum action = ActionEnum.None, bool required = false) => Add(nameOrFlag, dest, required, false, action, null);

        public void Add(string nameOrFlag, string dest, bool required = false, bool isNum = false, ActionEnum action = ActionEnum.None, string default_ = null)
        {
            var argument = new Argument(nameOrFlag, "", dest, default_, required, isNum, action);
            if (nameOrFlag.StartsWith("-"))
            {
                string flag = "";
                string name = nameOrFlag;
                if (nameOrFlag.Contains("|") || nameOrFlag.Contains(","))
                {
                    var nameOrFlags = nameOrFlag.Split(new char[] { '|', ',' }, 2);
                    if (nameOrFlags[0].StartsWith("--"))
                    {
                        name = nameOrFlags[0];
                        flag = nameOrFlags[1];
                    }
                    else if (nameOrFlags[1].StartsWith("--"))
                    {
                        flag = nameOrFlags[0];
                        name = nameOrFlags[1];
                    }
                    argument.Name = name;
                    argument.Flag = flag;
                }
                else if (!nameOrFlag.StartsWith("--"))
                {
                    argument.Flag = name;
                    flag = name;
                }

                if (name.Length > dashMaxLen) dashMaxLen = name.Length;
                if (flag.Length > flagMaxLen) flagMaxLen = flag.Length;
                if (flag.Length > 0 && DashFlags.Contains(flag)) throw new Exception(string.Format("forbid setting the flag({0}) repeatedly", flag));
                if (name.Length > 0 && DashNames.Contains(name)) throw new Exception(string.Format("forbid setting the name({0}) repeatedly", name));
                Names.Add(flag);
                Names.Add(name);
                DashFlags.Add(flag);
                DashNames.Add(name);
                ArgDashs.Add(argument);
            }
            else
            {
                Names.Add(nameOrFlag);
                Args.Add(argument);

                if (nameOrFlag.Length > nameMaxLen) nameMaxLen = nameOrFlag.Length;
            }
        }

        public void ParseArgs()
        {
            var argVals = Environment.GetCommandLineArgs();
            int currentArgIdx = 0;
            for (int idx = 1; idx < argVals.Length; idx++)
            {
                Argument arg = default;
                var argVal = argVals[idx];
                bool isDash = argVal.StartsWith("-");
                if (isDash && Names.Contains(argVal))
                {
                    bool isDoubleDash = argVal.StartsWith("--");
                    int dashIdx = isDoubleDash ? DashNames.IndexOf(argVal) : DashFlags.IndexOf(argVal);
                    arg = ArgDashs[dashIdx];
                    bool actionTrue = arg.Action == ActionEnum.StoreTrue;
                    bool actionFalse = arg.Action == ActionEnum.StoreFalse;
                    bool actionCount = arg.Action == ActionEnum.Count;
                    if (actionTrue) arg.Value = "true";
                    else if (actionFalse) arg.Value = "false";
                    else if (actionCount)
                    {
                        int.TryParse(arg.Value, out int cnt);
                        arg.Value = (++cnt).ToString();
                    }
                    else if (idx + 1 < argVals.Length)
                    {
                        var strArgNext = argVals[idx + 1];
                        if (arg.Default != null && Names.Contains(strArgNext)) arg.Value = arg.Default;
                        else
                        {
                            idx++;
                            arg.Value = strArgNext;
                        }
                    }
                    else if (idx + 1 == argVals.Length && arg.Default != null) arg.Value = arg.Default;
                    else Error(string.Format("unrecognized arguments: {0}\n", argVal));

                    ArgDashs[dashIdx] = arg;
                }
                else if (!isDash && currentArgIdx < Args.Count)
                {
                    arg = Args[currentArgIdx];
                    arg.Value = argVal;
                    Args[currentArgIdx++] = arg;
                }
                else Error(string.Format("unrecognized arguments: {0}\n", argVal));

                if (arg.IsNum && !double.TryParse(arg.Value, out _)) Error(string.Format("{0} argument must be numeric, value: {1}\n", arg.Name, arg.Value));
            }
        }

        public void Error(string message, bool showUsage = true, int exitCode = -1)
        {
            Console.Error.WriteLine(message + "\n");
            if (showUsage) PrintUsage();
            Environment.Exit(exitCode);
        }

        public void PrintUsage()
        {
            if (Usage.Length == 0)
            {
                if (Description.Length > 0) Usage = string.Format("{0}\n\n", Description);

                string programName = "";
                try { programName = Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0]); } catch (Exception) { }
                Usage += "Usage: " + programName + " ";
                string dashInfo1 = "", dashInfo2 = "", dashInfo3 = "", dashInfo4 = "";
                foreach (var arg in ArgDashs)
                {
                    string dest = arg.Dest.Length > 0 ? "<" + arg.Dest + ">" : "";
                    string required = arg.Required ? "(required)" : "";
                    string default_ = arg.Default != null ? ", default:" + arg.Default : "";
                    string destInfo = string.Format("{0}{1}{2}", dest, required, default_);
                    if (arg.Flag.Length == 0)
                    {
                        if (arg.Action == ActionEnum.None)
                             dashInfo1 += string.Format(" {0,-" + (flagMaxLen + dashMaxLen + 2) + "} {1}\n", arg.Name + " arg", destInfo);
                        else dashInfo3 += string.Format(" {0,-" + (flagMaxLen + dashMaxLen + 2) + "} {1}\n", arg.Name, destInfo);
                    }
                    else
                    {
                        if (arg.Action == ActionEnum.None)
                             dashInfo2 += string.Format(" {0,-" + flagMaxLen + "}, {1,-" + dashMaxLen + "} {2}\n", arg.Flag, arg.Name + " arg", destInfo);
                        else dashInfo4 += string.Format(" {0,-" + flagMaxLen + "}, {1,-" + dashMaxLen + "} {2}\n", arg.Flag, arg.Name, destInfo);
                    }
                }

                foreach (var arg in Args)
                {
                    if (arg.Required) Usage += string.Format("{0} ", arg.Name);
                    else Usage += string.Format("[{0}] ", arg.Name);
                }
                if (dashInfo1.Length > 0 || dashInfo2.Length > 0 || dashInfo3.Length > 0 || dashInfo4.Length > 0) Usage += "[Options] ";
                string info = "\n\n";
                foreach (var arg in Args)
                {
                    string dest = arg.Dest.Length > 0 ? "<" + arg.Dest + ">" : "";
                    string required = arg.Required ? "(required)" : "";
                    info += string.Format(" {0,-" + nameMaxLen + "} {1}{2}\n", arg.Name, dest, required);
                }

                if (info.Length > 0) Usage += info;
                if (dashInfo1.Length > 0 || dashInfo2.Length > 0 || dashInfo3.Length > 0 || dashInfo4.Length > 0) Usage += "\nOptions:\n";
                if (dashInfo1.Length > 0) Usage += dashInfo1;
                if (dashInfo2.Length > 0) Usage += dashInfo2;
                if (dashInfo1.Length > 0 || dashInfo2.Length > 0) Usage += "\n";
                if (dashInfo3.Length > 0) Usage += dashInfo3;
                if (dashInfo4.Length > 0) Usage += dashInfo4;
            }
            Console.WriteLine(Usage);
        }
    }
}