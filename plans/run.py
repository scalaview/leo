from plan import Plan
import os

if __name__ == "__main__":
    ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
    cron = Plan("commands")
    cron.command('cd %s/.. && %s/../bin/python3 %s/sync_order_state.py'%(ROOT_PATH, ROOT_PATH, ROOT_PATH), every='5.minute', output=
                   dict(stdout='%s/../log/sync_order_state_stdout.log'%ROOT_PATH,
                    stderr='%s/../log/sync_order_state_stderr.log'%ROOT_PATH))

    cron.run("check")
    cron.run("update")