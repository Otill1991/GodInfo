using System.Collections.Generic;

namespace GodInfo.Commands
{
    public interface ICommand
    {
        void Execute(List<string> args);
    }
}