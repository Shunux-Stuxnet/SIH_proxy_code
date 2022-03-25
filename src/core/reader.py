import json 

def read_json(location:str):
    f=open(location)
    data=json.load(f)
    f.close()
    return data
    
            