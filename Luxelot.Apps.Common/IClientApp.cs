﻿using System.Windows.Input;

namespace Luxelot.Apps.Common;

public interface IClientApp
{
    public string Name { get; }

    public string? InteractiveCommand { get; }

    public List<IConsoleCommand> Commands { get; }

    public void OnInitialize(IAppContext appContext);

    public Task OnActivate(CancellationToken cancellationToken);
    public Task OnDeactivate(CancellationToken cancellationToken);

    public Task<HandleUserInputResult> HandleUserInput(string input, CancellationToken cancellationToken);
}
