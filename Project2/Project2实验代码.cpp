#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <errno.h>

// BMP�ļ�ͷ�ṹ
typedef struct {
    unsigned short bfType;
    unsigned int bfSize;
    unsigned short bfReserved1;
    unsigned short bfReserved2;
    unsigned int bfOffBits;
} BMPFILEHEADER;

// BMP��Ϣͷ�ṹ
typedef struct {
    unsigned int biSize;
    int biWidth;
    int biHeight;
    unsigned short biPlanes;
    unsigned short biBitCount;
    unsigned int biCompression;
    unsigned int biSizeImage;
    int biXPelsPerMeter;
    int biYPelsPerMeter;
    unsigned int biClrUsed;
    unsigned int biClrImportant;
} BMPINFOHEADER;

// ��ȡBMPͼ��ʹ��fopen_s���fopen��
unsigned char* readBMP(const char* filename, BMPFILEHEADER* fileHeader, BMPINFOHEADER* infoHeader) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, filename, "rb");
    if (err != 0 || file == NULL) {
        printf("�޷����ļ�: %s (������: %d)\n", filename, err);
        return NULL;
    }

    // ��ȡ�ļ�ͷ
    fread(fileHeader, sizeof(BMPFILEHEADER), 1, file);
    if (fileHeader->bfType != 0x4D42) { // "BM"��ʶ���
        printf("������Ч��BMP�ļ�\n");
        fclose(file);
        return NULL;
    }

    // ��ȡ��Ϣͷ
    fread(infoHeader, sizeof(BMPINFOHEADER), 1, file);

    // ��֧��24λ���ɫ
    if (infoHeader->biBitCount != 24) {
        printf("���󣺽�֧��24λ���ɫBMP�ļ�\n");
        fclose(file);
        return NULL;
    }

    // �������ֽ�����4�ֽڶ��룩
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    int imageSize = widthBytes * abs(infoHeader->biHeight);

    // ����ͼ�������ڴ�
    unsigned char* imageData = (unsigned char*)malloc(imageSize);
    if (imageData == NULL) {
        printf("�ڴ����ʧ�ܣ��޷�����ͼ�����ݻ�����\n");
        fclose(file);
        return NULL;
    }

    // ��λ������������
    fseek(file, fileHeader->bfOffBits, SEEK_SET);
    fread(imageData, imageSize, 1, file);
    fclose(file);

    return imageData;
}

// ����BMPͼ��ʹ��fopen_s���fopen��
int saveBMP(const char* filename, BMPFILEHEADER* fileHeader, BMPINFOHEADER* infoHeader, unsigned char* imageData) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, filename, "wb");
    if (err != 0 || file == NULL) {
        printf("�޷������ļ�: %s (������: %d)\n", filename, err);
        return 0;
    }

    // �����ļ���С����ѡ�����ֳ�����Ҫ��
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    fileHeader->bfSize = sizeof(BMPFILEHEADER) + sizeof(BMPINFOHEADER) + widthBytes * abs(infoHeader->biHeight);

    // д���ļ�ͷ����Ϣͷ
    fwrite(fileHeader, sizeof(BMPFILEHEADER), 1, file);
    fwrite(infoHeader, sizeof(BMPINFOHEADER), 1, file);

    // д����������
    fwrite(imageData, widthBytes * abs(infoHeader->biHeight), 1, file);
    fclose(file);

    return 1;
}

// Ƕ��ˮӡ��LSB�㷨��
void embedWatermark(unsigned char* imageData, BMPINFOHEADER* infoHeader, const char* watermark, int watermarkLen) {
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    int maxCapacity = (infoHeader->biWidth * abs(infoHeader->biHeight) * 3) / 8; // 3ͨ����ÿ�ֽ�8λ

    if (watermarkLen > maxCapacity) {
        printf("���棺ˮӡ������ʵ��Ƕ�볤�Ƚ����ض�Ϊ %d �ֽ�\n", maxCapacity);
        watermarkLen = maxCapacity;
    }

    int bitIndex = 0;
    int byteIndex = 0;
    unsigned char currentByte = watermark[byteIndex];

    // ��������Ƕ��ˮӡ
    for (int i = 0; i < abs(infoHeader->biHeight); i++) {
        for (int j = 0; j < infoHeader->biWidth; j++) {
            int pos = i * widthBytes + j * 3;
            for (int k = 0; k < 3; k++) { // B/G/Rͨ��
                if (byteIndex >= watermarkLen) return;

                // ������λ������ˮӡλ
                imageData[pos + k] &= 0xFE;
                imageData[pos + k] |= (currentByte >> (7 - bitIndex)) & 0x01;

                if (++bitIndex == 8) {
                    bitIndex = 0;
                    currentByte = watermark[++byteIndex];
                }
            }
        }
    }
}

// ��ȡˮӡ
void extractWatermark(unsigned char* imageData, BMPINFOHEADER* infoHeader, char* watermark, int maxLen) {
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    int maxCapacity = (infoHeader->biWidth * abs(infoHeader->biHeight) * 3) / 8;
    if (maxLen > maxCapacity) maxLen = maxCapacity;

    memset(watermark, 0, maxLen + 1); // ȷ����ֹ������
    unsigned char currentByte = 0;
    int bitIndex = 0, byteIndex = 0;

    // ����������ȡˮӡ
    for (int i = 0; i < abs(infoHeader->biHeight); i++) {
        for (int j = 0; j < infoHeader->biWidth; j++) {
            int pos = i * widthBytes + j * 3;
            for (int k = 0; k < 3; k++) { // B/G/Rͨ��
                if (byteIndex >= maxLen) return;

                // ��ȡ���λ
                currentByte |= ((imageData[pos + k] & 0x01) << (7 - bitIndex));
                if (++bitIndex == 8) {
                    bitIndex = 0;
                    watermark[byteIndex++] = currentByte;
                    currentByte = 0;
                }
            }
        }
    }
}

// ˮƽ��תͼ��
void flipImageHorizontal(unsigned char* imageData, BMPINFOHEADER* infoHeader) {
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    int halfWidth = infoHeader->biWidth / 2;

    for (int i = 0; i < abs(infoHeader->biHeight); i++) {
        for (int j = 0; j < halfWidth; j++) {
            int leftPos = i * widthBytes + j * 3;
            int rightPos = i * widthBytes + (infoHeader->biWidth - 1 - j) * 3;

            // ����B/G/Rͨ������
            for (int k = 0; k < 3; k++) {
                unsigned char temp = imageData[leftPos + k];
                imageData[leftPos + k] = imageData[rightPos + k];
                imageData[rightPos + k] = temp;
            }
        }
    }
}

// �����Աȶȣ���ʽ��new = factor*(old-128)+128��
void adjustContrast(unsigned char* imageData, BMPINFOHEADER* infoHeader, float contrast) {
    int widthBytes = (infoHeader->biWidth * 3 + 3) & ~3;
    float factor = (259.0f * (contrast + 255.0f)) / (255.0f * (259.0f - contrast));

    for (int i = 0; i < abs(infoHeader->biHeight); i++) {
        for (int j = 0; j < infoHeader->biWidth; j++) {
            int pos = i * widthBytes + j * 3;
            for (int k = 0; k < 3; k++) { // ����ÿ��ͨ��
                int val = (int)(factor * (imageData[pos + k] - 128) + 128);
                imageData[pos + k] = (unsigned char)(val < 0 ? 0 : (val > 255 ? 255 : val));
            }
        }
    }
}

// ��ȡͼ�񣨷�����ͼ�����ݣ����ⲿ�ͷţ�
unsigned char* cropImage(unsigned char* originalData, BMPINFOHEADER* originalHeader,
    BMPINFOHEADER* croppedHeader, int x, int y, int width, int height) {
    // �߽���
    if (x < 0 || y < 0 || x + width > originalHeader->biWidth || y + height > abs(originalHeader->biHeight)) {
        printf("���󣺽�ȡ���򳬳�ͼ��Χ\n");
        return NULL;
    }

    // ��ʼ����ͼ��ͷ
    *croppedHeader = *originalHeader;
    croppedHeader->biWidth = width;
    croppedHeader->biHeight = originalHeader->biHeight > 0 ? height : -height;

    int originalWidthBytes = (originalHeader->biWidth * 3 + 3) & ~3;
    int croppedWidthBytes = (width * 3 + 3) & ~3;
    size_t croppedImageSize = (size_t)croppedWidthBytes * height;

    // �����ڴ�
    unsigned char* croppedData = (unsigned char*)malloc(croppedImageSize);
    if (croppedData == NULL) {
        printf("�ڴ����ʧ�ܣ��޷�������ȡͼ�񻺳���\n");
        return NULL;
    }

    // ������������
    for (int i = 0; i < height; i++) {
        int originalRow = y + i;
        if (originalHeader->biHeight < 0) { // ������洢��BMP
            originalRow = abs(originalHeader->biHeight) - 1 - y - i;
        }

        size_t originalPos = (size_t)originalRow * originalWidthBytes + x * 3;
        size_t croppedPos = (size_t)i * croppedWidthBytes;
        memcpy(&croppedData[croppedPos], &originalData[originalPos], (size_t)width * 3);
    }

    return croppedData;
}

// ƽ��ͼ�񣨷�����ͼ�����ݣ����ⲿ�ͷţ�
unsigned char* translateImage(unsigned char* originalData, BMPINFOHEADER* originalHeader,
    int dx, int dy) {
    int widthBytes = (originalHeader->biWidth * 3 + 3) & ~3;
    size_t imageSize = (size_t)widthBytes * abs(originalHeader->biHeight);

    // �����ڴ沢��ʼ��Ϊ��ɫ
    unsigned char* translatedData = (unsigned char*)malloc(imageSize);
    if (translatedData == NULL) {
        printf("�ڴ����ʧ�ܣ��޷�����ƽ��ͼ�񻺳���\n");
        return NULL;
    }
    memset(translatedData, 0, imageSize);

    // ƽ�ƴ���
    for (int i = 0; i < abs(originalHeader->biHeight); i++) {
        for (int j = 0; j < originalHeader->biWidth; j++) {
            int newX = j + dx;
            int newY = i + dy;

            // ���Ŀ��λ����Ч��
            if (newX >= 0 && newX < originalHeader->biWidth && newY >= 0 && newY < abs(originalHeader->biHeight)) {
                size_t originalPos = (size_t)i * widthBytes + j * 3;
                size_t newPos = (size_t)newY * widthBytes + newX * 3;

                // �������أ�B/G/R��
                for (int k = 0; k < 3; k++) {
                    translatedData[newPos + k] = originalData[originalPos + k];
                }
            }
        }
    }

    return translatedData;
}

int main() {
    BMPFILEHEADER fileHeader;
    BMPINFOHEADER infoHeader;

    // 1. ��ȡԭʼͼ��
    unsigned char* originalImage = readBMP("D:\\Project2\\Debug\\original.bmp", &fileHeader, &infoHeader);
    if (originalImage == NULL) {
        printf("������ȷ����ǰĿ¼����original.bmp��24λBMP��ʽ��\n");
        system("pause");
        return 1;
    }

    // 2. ����ˮӡ�����鳤�Ȳ�����ͼ��������
    const char* watermarkText = "Confidential_Document_2025";
    int watermarkLen = (int)strlen(watermarkText); // ��ʽת��size_t��int

    // 3. ������ˮӡ��ͼ�񸱱�
    int widthBytes = (infoHeader.biWidth * 3 + 3) & ~3;
    size_t imageSize = (size_t)widthBytes * abs(infoHeader.biHeight);

    unsigned char* watermarkedImage = (unsigned char*)malloc(imageSize);
    if (watermarkedImage == NULL) {
        printf("�ڴ����ʧ�ܣ��޷�����ˮӡͼ�񸱱�\n");
        free(originalImage);
        system("pause");
        return 1;
    }
    memcpy(watermarkedImage, originalImage, imageSize);

    // 4. Ƕ��ˮӡ
    embedWatermark(watermarkedImage, &infoHeader, watermarkText, watermarkLen);
    saveBMP("watermarked.bmp", &fileHeader, &infoHeader, watermarkedImage);
    printf("[+] ˮӡ��Ƕ�룺watermarked.bmp\n");

    // 5. ��ȡԭʼˮӡ��֤
    char extractedOriginal[512] = { 0 };
    extractWatermark(watermarkedImage, &infoHeader, extractedOriginal, sizeof(extractedOriginal) - 1);
    printf("[��] ԭʼˮӡ��ȡ��%s\n", extractedOriginal);

    // 6. ³���Բ��ԣ�ˮƽ��ת
    unsigned char* flippedImage = (unsigned char*)malloc(imageSize);
    if (flippedImage == NULL) {
        printf("�ڴ����ʧ�ܣ��޷�������תͼ�񻺳���\n");
        free(originalImage);
        free(watermarkedImage);
        system("pause");
        return 1;
    }
    memcpy(flippedImage, watermarkedImage, imageSize);
    flipImageHorizontal(flippedImage, &infoHeader);
    saveBMP("flipped.bmp", &fileHeader, &infoHeader, flippedImage);

    char extractedFlipped[512] = { 0 };
    extractWatermark(flippedImage, &infoHeader, extractedFlipped, sizeof(extractedFlipped) - 1);
    printf("[��ת����] ��ȡˮӡ��%s\n", extractedFlipped);

    // 7. ³���Բ��ԣ������Աȶȣ�+80��
    unsigned char* contrastImage = (unsigned char*)malloc(imageSize);
    if (contrastImage == NULL) {
        printf("�ڴ����ʧ�ܣ��޷������Աȶ�ͼ�񻺳���\n");
        free(originalImage);
        free(watermarkedImage);
        free(flippedImage);
        system("pause");
        return 1;
    }
    memcpy(contrastImage, watermarkedImage, imageSize);
    adjustContrast(contrastImage, &infoHeader, 80.0f); // ��ǿ�Աȶ�
    saveBMP("contrast.bmp", &fileHeader, &infoHeader, contrastImage);

    char extractedContrast[512] = { 0 };
    extractWatermark(contrastImage, &infoHeader, extractedContrast, sizeof(extractedContrast) - 1);
    printf("[�ԱȶȲ���] ��ȡˮӡ��%s\n", extractedContrast);

    // 8. ³���Բ��ԣ�ͼ���ȡ����������
    BMPINFOHEADER croppedHeader;
    int cropX = infoHeader.biWidth / 4;
    int cropY = abs(infoHeader.biHeight) / 4;
    int cropW = infoHeader.biWidth / 2;
    int cropH = abs(infoHeader.biHeight) / 2;

    unsigned char* croppedImage = cropImage(watermarkedImage, &infoHeader, &croppedHeader, cropX, cropY, cropW, cropH);
    if (croppedImage != NULL) {
        BMPFILEHEADER croppedFileHeader = fileHeader;
        croppedFileHeader.bfSize = sizeof(BMPFILEHEADER) + sizeof(BMPINFOHEADER) +
            (croppedHeader.biWidth * 3 + 3) / 4 * 4 * abs(croppedHeader.biHeight);

        saveBMP("cropped.bmp", &croppedFileHeader, &croppedHeader, croppedImage);

        char extractedCropped[512] = { 0 };
        extractWatermark(croppedImage, &croppedHeader, extractedCropped, sizeof(extractedCropped) - 1);
        printf("[��ȡ����] ��ȡˮӡ��%s\n", extractedCropped);
        free(croppedImage);
    }

    // 9. ³���Բ��ԣ�ͼ��ƽ�ƣ�����30������20��
    unsigned char* translatedImage = translateImage(watermarkedImage, &infoHeader, 30, 20);
    if (translatedImage != NULL) {
        saveBMP("translated.bmp", &fileHeader, &infoHeader, translatedImage);

        char extractedTranslated[512] = { 0 };
        extractWatermark(translatedImage, &infoHeader, extractedTranslated, sizeof(extractedTranslated) - 1);
        printf("[ƽ�Ʋ���] ��ȡˮӡ��%s\n", extractedTranslated);
        free(translatedImage);
    }

    // 10. �ͷ���Դ
    free(originalImage);
    free(watermarkedImage);
    free(flippedImage);
    free(contrastImage);

    printf("\n���в�����ɣ���������˳�...\n");
    system("pause");
    return 0;
}