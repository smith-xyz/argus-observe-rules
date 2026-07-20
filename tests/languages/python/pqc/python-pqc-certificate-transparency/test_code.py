from ct.client import log_client

def query_ct_log(url, pubkey):
    client = log_client.LogClient(url, "json", pubkey)
    sth = client.get_sth()
    entries = client.get_entries(0, 10)
    return sth, entries
