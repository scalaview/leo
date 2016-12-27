#! /bin/bash
cd $1
source bin/activate

python3 sync_order_state.py
deactivate