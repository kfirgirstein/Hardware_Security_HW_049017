
def get_text_stat(text):
    '''
    This function gets the current text statistics
    '''
    stat = {}
    text = text
    
    for i in text:
        if(len(str(hex(ord(i)))[2:]) == 2):
            value = str(hex(ord(i)))[2:]
        else:
            value = "0" + str(hex(ord(i)))[2:]
            
        if value in stat:
            stat[value] += 1
        else:
            stat[value] = 1
    
    return stat