/*
 * @Author: 13561 1356137745@qq.com
 * @Date: 2024-10-25 11:43:46
 * @LastEditors: 13561 1356137745@qq.com
 * @LastEditTime: 2024-10-25 11:59:40
 * @FilePath: \lab4\casesar_cipher.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <windows.h>
#include <stdio.h>

#define ID_TEXTBOX_INPUT 1
#define ID_EDIT_KEY 2
#define ID_BUTTON_ENCRYPT 3
#define ID_BUTTON_DECRYPT 4
#define ID_TEXTBOX_OUTPUT 5
#define ID_LABEL_INPUT 6   // 添加输入标签的标识符
#define ID_LABEL_OUTPUT 7  // 添加输出标签的标识符


LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hInput, hOutput, hKey;

switch (uMsg) {
    case WM_CREATE:
        // 创建输入标签
        CreateWindow("STATIC", "INPUT:", WS_VISIBLE | WS_CHILD, 10, 10, 100, 20, hwnd, (HMENU)ID_LABEL_INPUT, NULL, NULL);
           
        // 创建输入文本框
        hInput = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 10, 30, 700, 150, hwnd, (HMENU)ID_TEXTBOX_INPUT, NULL, NULL);
        
        // 输出
        CreateWindow("STATIC", "OUTPUT:", WS_VISIBLE | WS_CHILD, 10, 200, 100, 20, hwnd, (HMENU)ID_LABEL_OUTPUT, NULL, NULL);

        // 创建输出文本框
        hOutput = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_READONLY | ES_AUTOHSCROLL, 10, 230, 700, 150, hwnd, (HMENU)ID_TEXTBOX_OUTPUT, NULL, NULL);
        
        // 创建密钥输入框
        hKey = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 80, 400, 60, 40, hwnd, (HMENU)ID_EDIT_KEY, NULL, NULL);
        
        // 创建加密按钮
        CreateWindow("BUTTON", "Encrypt", WS_VISIBLE | WS_CHILD, 250, 400, 150, 40, hwnd, (HMENU)ID_BUTTON_ENCRYPT, NULL, NULL);
        
        // 创建解密按钮
        CreateWindow("BUTTON", "Decrypt", WS_VISIBLE | WS_CHILD, 420, 400, 150, 40, hwnd, (HMENU)ID_BUTTON_DECRYPT, NULL, NULL);
        break;



        case WM_COMMAND:
            if (LOWORD(wParam) == ID_BUTTON_ENCRYPT || LOWORD(wParam) == ID_BUTTON_DECRYPT) {
                char inputText[256];
                GetWindowText(hInput, inputText, sizeof(inputText));

                int key;
                char keyText[10];
                GetWindowText(hKey, keyText, sizeof(keyText));
                sscanf(keyText, "%d", &key);

                if (LOWORD(wParam) == ID_BUTTON_ENCRYPT) {
                    // 加密
                    for (int i = 0; inputText[i] != '\0'; i++) {
                        char c = inputText[i];
                        if (c >= 'a' && c <= 'z') {
                            inputText[i] = (c - 'a' + key) % 26 + 'a';
                        } else if (c >= 'A' && c <= 'Z') {
                            inputText[i] = (c - 'A' + key) % 26 + 'A';
                        }
                    }
                } else {
                    // 解密
                    for (int i = 0; inputText[i] != '\0'; i++) {
                        char c = inputText[i];
                        if (c >= 'a' && c <= 'z') {
                            inputText[i] = (c - 'a' + (26 - (key % 26))) % 26 + 'a';
                        } else if (c >= 'A' && c <= 'Z') {
                            inputText[i] = (c - 'A' + (26 - (key % 26))) % 26 + 'A';
                        }
                    }
                }

                // 显示结果
                SetWindowText(hOutput, inputText);
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    const char CLASS_NAME[] = "CaesarCipherClass";

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0, CLASS_NAME, "CaesarCipher", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nShowCmd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
