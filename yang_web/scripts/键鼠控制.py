#!/usr/bin/env python

# import pyautogui

# width,height=pyautogui.size()
# print(width,height,sep="\n")
# #ç§»å¨é¼ æ å°æå®ä½ç½®durationä¸ºæç»­æ¶é´
# pyautogui.moveTo(500,500,duration=0.25)
# pyautogui.doubleClick(x=100, y=150, button="left") # é¼ æ å¨ï¼100ï¼150ï¼ä½ç½®å·¦å»ä¸¤ä¸
# pyautogui.tripleClick() # é¼ æ å½åä½ç½®å·¦å»ä¸ä¸
# pyautogui.mouseDown() # é¼ æ å·¦é®æä¸åæ¾å¼
# pyautogui.mouseUp()
# pyautogui.mouseDown(button='right') # æä¸é¼ æ å³é®
# pyautogui.mouseUp(button='right', x=100, y=200) # ç§»å¨å°(100, 200)ä½ç½®ï¼ç¶åæ¾å¼é¼ æ å³é®
 


# #ç¸å¯¹å½åä½ç½®ç§»å¨é¼ æ 
# pyautogui.moveRel(100,0,duration=0.25)

# #è·åé¼ æ ä½ç½® position()
# a=pyautogui.position()
# print(a)

# #click()ï¼é¼ æ åå»
# #doubleClick()ï¼é¼ æ åå»
# #rightClick()ï¼é¼ æ å³å»
# pyautogui.click(500,500)

#dragTo()ï¼æä½ç§»å¨é¼ æ å°ä¸ä¸ªä½ç½®
#dragRel()ï¼æä½ç§»å¨é¼ æ å°ä¸ä¸ªç¸å¯¹ä½ç½®
# æä½é¼ æ å·¦é®ï¼æé¼ æ ææ½å°(100, 200)ä½ç½®
# pyautogui.dragTo(100, 200, button='left')
# æä½é¼ æ å·¦é®ï¼ç¨2ç§éæé¼ æ ææ½å°(300, 400)ä½ç½®
# pyautogui.dragTo(300, 400, 2, button='left')
# æä½é¼ æ å·¦é®ï¼ç¨0.2ç§éæé¼ æ åä¸ææ½
# pyautogui.dragRel(0, -60, duration=0.2)

#æ»å¨é¼ æ         scoll()å½æ°
# pyautogui.scroll(10) # åä¸æ»å¨10æ ¼
# pyautogui.scroll(-10) # åä¸æ»å¨10æ ¼
# pyautogui.scroll(10, x=100, y=100) # ç§»å¨å°(100, 100)ä½ç½®ååä¸æ»å¨10æ ¼

# å¼å§å¾æ¢ï¼ä¸æ­å é
# pyautogui.moveTo(100, 100, 2, pyautogui.easeInQuad)
# # å¼å§å¾å¿«ï¼ä¸æ­åé
# pyautogui.moveTo(100, 100, 2, pyautogui.easeOutQuad)
# # å¼å§åç»æé½å¿«ï¼ä¸­é´æ¯è¾æ¢
# pyautogui.moveTo(100, 100, 2, pyautogui.easeInOutQuad)
# # ä¸æ­¥ä¸å¾å¾åè¿
# pyautogui.moveTo(100, 100, 2, pyautogui.easeInBounce)
# # å¾å¾å¹åº¦æ´å¤§ï¼çè³è¶è¿èµ·ç¹åç»ç¹
# pyautogui.moveTo(100, 100, 2, pyautogui.easeInElastic)

# è·åå±å¹å¿«ç§        screenshot()å½æ°
# import pyautogui
# im=pyautogui.screenshot()
# im.getpixel((0,0))
# im.getpixel((50,200))
# im.show()
# im.save("111.png")

# éè¿é®çåéå­ç¬¦ä¸²        typewrite()å½æ°
# import pyautogui
# pyautogui.click(500,500)
# pyautogui.typewrite('hello world')
# # æä¸ãéæ¾é®ç
# pyautogui.keyDown("S")#ï¼æä¸é®ç
# pyautogui.keyUp("S")#ï¼éæ¾æé®
# pyautogui.hotkey('command','z')        #æä¸ç­é®ctrl+c


#ââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
# æ¡ä¾è·åé¼ æ çä½ç½®åé¢è²ï¼æ¹ä¾¿å¤å¶æä»¬å®ä½çé¼ æ åæ ç¹å°ä»£ç ä¸­
# import pyautogui
# import time
# # è·åé¼ æ ä½ç½®
# def get_mouse_positon():
#   time.sleep(5) # åå¤æ¶é´
#   print('å¼å§è·åé¼ æ ä½ç½®')
#   try:
#     for i in range(10):
#       # Get and print the mouse coordinates.
#       x, y = pyautogui.position()
#       positionStr = 'é¼ æ åæ ç¹ï¼X,Yï¼ä¸ºï¼{},{}'.format(str(x).rjust(4), str(y).rjust(4))
#       pix = pyautogui.screenshot().getpixel((x, y)) # è·åé¼ æ æå¨å±å¹ç¹çRGBé¢è²
#       positionStr += ' RGB:(' + str(pix[0]).rjust(3) + ',' + str(pix[1]).rjust(3) + ',' + str(pix[2]).rjust(
#         3) + ')'
#       print(positionStr)
#       time.sleep(0.5) # åé¡¿æ¶é´
#   except:
#     print('è·åé¼ æ ä½ç½®å¤±è´¥')
# if __name__ == "__main__":
#   get_mouse_positon()
#ââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

#æ¡ä¾è·åé¼ æ çä½ç½®åé¢è²2
# import pyautogui
 
# print('Press Ctrl-C to quit.')
# try:
#   while True:
#     # Get and print the mouse coordinates.
#     x, y = pyautogui.position()
#     positionStr = 'X:' + str(x).rjust(4) + ' Y:' + str(y).rjust(4)
#     pix = pyautogui.screenshot().getpixel((x, y)) # è·åé¼ æ æå¨å±å¹ç¹çRGBé¢è²
#     positionStr += ' RGB:(' + str(pix[0]).rjust(3) + ',' + str(pix[1]).rjust(3) + ',' + str(pix[2]).rjust(3) + ')'
#     print(positionStr, end='') # end='' æ¿æ¢äºé»è®¤çæ¢è¡
#     print('\b' * len(positionStr), end='', flush=True) # è¿ç»­éæ ¼é®å¹¶å·æ°ï¼å é¤ä¹åæå°çåæ ï¼å°±åç´æ¥æ´æ°åæ ææ
# except KeyboardInterrupt: # å¤ç Ctrl-C æé®
#   print('\nDone.')


#é®ç
# import pyautogui
 
# pyautogui.typewrite('Hello world!') # è¾å¥Hello world!å­ç¬¦ä¸²
# pyautogui.typewrite('Hello world!', interval=0.25) # æ¯æ¬¡è¾å¥é´é0.25ç§ï¼è¾å¥Hello world!
 
# pyautogui.press('enter') # æä¸å¹¶æ¾å¼ï¼è½»æ²ï¼åè½¦é®
# pyautogui.press(['left', 'left', 'left', 'left']) # æä¸å¹¶æ¾å¼ï¼è½»æ²ï¼åä¸å·¦æ¹åé®
# pyautogui.keyDown('shift') # æä¸`shift`é®
# pyautogui.keyUp('shift') # æ¾å¼`shift`é®
 
# pyautogui.keyDown('shift')
# pyautogui.press('4')
# pyautogui.keyUp('shift') # è¾åº $ ç¬¦å·çæé®
 
# pyautogui.hotkey('ctrl', 'v') # ç»åæé®ï¼Ctrl+Vï¼ï¼ç²è´´åè½ï¼æä¸å¹¶æ¾å¼'ctrl'å'v'æé®
 
# # pyautogui.KEYBOARD_KEYSæ°ç»ä¸­å°±æ¯press()ï¼keyDown()ï¼keyUp()åhotkey()å½æ°å¯ä»¥è¾å¥çæé®åç§°
# pyautogui.KEYBOARD_KEYS = ['\t', '\n', '\r', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.',
            #   '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@',
            #   '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            #   'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~',
            #   'accept', 'add', 'alt', 'altleft', 'altright', 'apps', 'backspace', 'browserback',
            #   'browserfavorites', 'browserforward', 'browserhome', 'browserrefresh', 'browsersearch',
            #   'browserstop', 'capslock', 'clear', 'convert', 'ctrl', 'ctrlleft', 'ctrlright', 'decimal',
            #   'del', 'delete', 'divide', 'down', 'end', 'enter', 'esc', 'escape', 'execute', 'f1', 'f10',
            #   'f11', 'f12', 'f13', 'f14', 'f15', 'f16', 'f17', 'f18', 'f19', 'f2', 'f20', 'f21', 'f22',
            #   'f23', 'f24', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'final', 'fn', 'hanguel', 'hangul',
            #   'hanja', 'help', 'home', 'insert', 'junja', 'kana', 'kanji', 'launchapp1', 'launchapp2',
            #   'launchmail', 'launchmediaselect', 'left', 'modechange', 'multiply', 'nexttrack',
            #   'nonconvert', 'num0', 'num1', 'num2', 'num3', 'num4', 'num5', 'num6', 'num7', 'num8', 'num9',
            #   'numlock', 'pagedown', 'pageup', 'pause', 'pgdn', 'pgup', 'playpause', 'prevtrack', 'print',
            #   'printscreen', 'prntscrn', 'prtsc', 'prtscr', 'return', 'right', 'scrolllock', 'select',
            #   'separator', 'shift', 'shiftleft', 'shiftright', 'sleep', 'space', 'stop', 'subtract', 'tab',
            #   'up', 'volumedown', 'volumemute', 'volumeup', 'win', 'winleft', 'winright', 'yen', 'command',
            #   'option', 'optionleft', 'optionright']

#å¼¹çªæä½
# import pyautogui
# # æ¾ç¤ºä¸ä¸ªç®åçå¸¦æå­åOKæé®çæ¶æ¯å¼¹çªãç¨æ·ç¹å»åè¿åbuttonçæå­ã
# pyautogui.alert(text='', title='', button='OK')
# b = pyautogui.alert(text='è¦å¼å§ç¨åºä¹ï¼', title='è¯·æ±æ¡', button='OK')
# print(b) # è¾åºç»æä¸ºOK
# # æ¾ç¤ºä¸ä¸ªç®åçå¸¦æå­ãOKåCancelæé®çæ¶æ¯å¼¹çªï¼ç¨æ·ç¹å»åè¿åè¢«ç¹å»buttonçæå­ï¼æ¯æèªå®ä¹æ°å­ãæå­çåè¡¨ã
# pyautogui.confirm(text='', title='', buttons=['OK', 'Cancel']) # OKåCancelæé®çæ¶æ¯å¼¹çª
# pyautogui.confirm(text='', title='', buttons=range(10)) # 10ä¸ªæé®0-9çæ¶æ¯å¼¹çª
# a = pyautogui.confirm(text='', title='', buttons=range(10))
# print(a) # è¾åºç»æä¸ºä½ éçæ°å­
# å¯ä»¥è¾å¥çæ¶æ¯å¼¹çªï¼å¸¦OKåCancelæé®ãç¨æ·ç¹å»OKæé®è¿åè¾å¥çæå­ï¼ç¹å»Cancelæé®è¿åNoneã
# pyautogui.prompt(text='', title='', default='')
# æ ·å¼åprompt()ï¼ç¨äºè¾å¥å¯ç ï¼æ¶æ¯ç¨*è¡¨ç¤ºãå¸¦OKåCancelæé®ãç¨æ·ç¹å»OKæé®è¿åè¾å¥çæå­ï¼ç¹å»Cancelæé®è¿åNoneã
# pyautogui.password(text='', title='', default='', mask='*')

#å¾åæä½
import pyautogui
 
pyautogui.screenshot(r'C:\Users\ZDH\Desktop\PY\my_screenshot.png') # æªå¨å±å¹¶è®¾ç½®ä¿å­å¾ççä½ç½®ååç§°
im = pyautogui.screenshot(r'C:\Users\ZDH\Desktop\PY\my_screenshot.png') # æªå¨å±å¹¶è®¾ç½®ä¿å­å¾ççä½ç½®ååç§°
print(im) # æå°å¾ççå±æ§
 
# ä¸æªå¨å±ï¼æªååºåå¾çãæªååºåregionåæ°ä¸ºï¼å·¦ä¸è§XYåæ å¼ãå®½åº¦åé«åº¦
pyautogui.screenshot(r'C:\Users\ZDH\Desktop\PY\region_screenshot.png', region=(0, 0, 300, 400))
 
pix = pyautogui.screenshot().getpixel((220, 200)) # è·ååæ (220,200)æå¨å±å¹ç¹çRGBé¢è²
positionStr = ' RGB:(' + str(pix[0]).rjust(3) + ',' + str(pix[1]).rjust(3) + ',' + str(pix[2]).rjust(3) + ')'
print(positionStr) # æå°ç»æä¸ºRGB:( 60, 63, 65)
pix = pyautogui.pixel(220, 200) # è·ååæ (220,200)æå¨å±å¹ç¹çRGBé¢è²ä¸ä¸é¢ä¸è¡ä»£ç ä½ç¨ä¸æ ·
positionStr = ' RGB:(' + str(pix[0]).rjust(3) + ',' + str(pix[1]).rjust(3) + ',' + str(pix[2]).rjust(3) + ')'
print(positionStr) # æå°ç»æä¸ºRGB:( 60, 63, 65)
 
# å¦æä½ åªæ¯è¦æ£éªä¸ä¸æå®ä½ç½®çåç´ å¼ï¼å¯ä»¥ç¨pixelMatchesColor(x,y,RGB)å½æ°ï¼æXãYåRGBåç»å¼ç©¿å¥å³å¯
# å¦ææå¨å±å¹ä¸­(x,y)ç¹çå®éRGBä¸è²ä¸å½æ°ä¸­çRGBä¸æ ·å°±ä¼è¿åTrueï¼å¦åè¿åFalse
# toleranceåæ°å¯ä»¥æå®çº¢ãç»¿ãè3ç§é¢è²è¯¯å·®èå´
pyautogui.pixelMatchesColor(100, 200, (255, 255, 255))
pyautogui.pixelMatchesColor(100, 200, (255, 255, 245), tolerance=10)
 
# è·å¾æä»¶å¾çå¨ç°å¨çå±å¹ä¸é¢çåæ ï¼è¿åçæ¯ä¸ä¸ªåç»(top, left, width, height)
# å¦ææªå¾æ²¡æ¾å°ï¼pyautogui.locateOnScreen()å½æ°è¿åNone
a = pyautogui.locateOnScreen(r'C:\Users\ZDH\Desktop\PY\region_screenshot.png')
print(a) # æå°ç»æä¸ºBox(left=0, top=0, width=300, height=400)
x, y = pyautogui.center(a) # è·å¾æä»¶å¾çå¨ç°å¨çå±å¹ä¸é¢çä¸­å¿åæ 
print(x, y) # æå°ç»æä¸º150 200
x, y = pyautogui.locateCenterOnScreen(r'C:\Users\ZDH\Desktop\PY\region_screenshot.png') # è¿æ­¥ä¸ä¸é¢çåè¡ä»£ç ä½ç¨ä¸æ ·
print(x, y) # æå°ç»æä¸º150 200
 
# å¹éå±å¹ææä¸ç®æ å¾ççå¯¹è±¡ï¼å¯ä»¥ç¨forå¾ªç¯ålist()è¾åº
pyautogui.locateAllOnScreen(r'C:\Users\ZDH\Desktop\PY\region_screenshot.png')
for pos in pyautogui.locateAllOnScreen(r'C:\Users\ZDH\Desktop\PY\region_screenshot.png'):
  print(pos)
# æå°ç»æä¸ºBox(left=0, top=0, width=300, height=400)
a = list(pyautogui.locateAllOnScreen(r'C:\Users\ZDH\Desktop\PY\region_screenshot.png'))
print(a) # æå°ç»æä¸º[Box(left=0, top=0, width=300, height=400)]
