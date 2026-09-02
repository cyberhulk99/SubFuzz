import subprocess

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def run_lookup(target):
    # Deliberately vulnerable: shell=True with unsanitized input, for Polaris SCR to catch
    subprocess.run(target, shell=True)
