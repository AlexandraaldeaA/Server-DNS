if ! command -v tmux &> /dev/null; then
    echo "Tmux nu este instalat. Instalează-l folosind: sudo apt install tmux"
    exit 1
fi

SESSION_NAME="dual_terminal"

tmux new-session -d -s $SESSION_NAME

tmux split-window -h

tmux setw synchronize-panes on

tmux attach-session -t $SESSION_NAME

