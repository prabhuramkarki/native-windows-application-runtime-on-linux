/* D3D11 render fixture (Phase 4E): renders offscreen (no window, no swapchain) through whatever d3d11.dll the
 * prefix loads -- DXVK once the `dxvk` package is installed.
 *   hardware device at feature level 11_0 -> 64x64 R8G8B8A8_UNORM render target -> 100 x (clear to
 *   (0.25, 0.5, 0.75, 1.0) + Flush), timed with QueryPerformanceCounter -> copy to a staging texture -> Map ->
 *   pixel (0,0) must be (64,128,191,255) +-1 per channel.
 * Prints `pixel ok` or `pixel BAD r g b a`, then `frame ms: <mean>` and `adapter: <DXGI description>`.
 * Exit 0 only on `pixel ok`; 1 on a wrong pixel; any failing HRESULT prints `fail: <call> 0x........` and exits 2.
 * WANT_R..WANT_A can be overridden with -D to check the wrong-pixel path. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef WANT_R
#define WANT_R 64
#endif
#ifndef WANT_G
#define WANT_G 128
#endif
#ifndef WANT_B
#define WANT_B 191
#endif
#ifndef WANT_A
#define WANT_A 255
#endif

static void check(HRESULT hr, const char *call) {
    if (FAILED(hr)) {
        printf("fail: %s 0x%08lx\n", call, (unsigned long)hr);
        fflush(stdout);
        exit(2);
    }
}

static int within1(int got, int want) {
    return abs(got - want) <= 1;
}

int main(void) {
    ID3D11Device *dev;
    ID3D11DeviceContext *ctx;
    D3D_FEATURE_LEVEL want = D3D_FEATURE_LEVEL_11_0, got;
    check(D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, &want, 1, D3D11_SDK_VERSION, &dev, &got, &ctx),
          "D3D11CreateDevice");

    D3D11_TEXTURE2D_DESC td = {0};
    td.Width = td.Height = 64;
    td.MipLevels = td.ArraySize = 1;
    td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_RENDER_TARGET;
    ID3D11Texture2D *target, *staging;
    check(ID3D11Device_CreateTexture2D(dev, &td, NULL, &target), "CreateTexture2D(target)");
    ID3D11RenderTargetView *rtv;
    check(ID3D11Device_CreateRenderTargetView(dev, (ID3D11Resource *)target, NULL, &rtv), "CreateRenderTargetView");

    const FLOAT color[4] = {0.25f, 0.5f, 0.75f, 1.0f};
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < 100; i++) {
        ID3D11DeviceContext_ClearRenderTargetView(ctx, rtv, color);
        ID3D11DeviceContext_Flush(ctx);
    }
    QueryPerformanceCounter(&t1);

    td.Usage = D3D11_USAGE_STAGING;
    td.BindFlags = 0;
    td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    check(ID3D11Device_CreateTexture2D(dev, &td, NULL, &staging), "CreateTexture2D(staging)");
    ID3D11DeviceContext_CopyResource(ctx, (ID3D11Resource *)staging, (ID3D11Resource *)target);
    D3D11_MAPPED_SUBRESOURCE map;
    check(ID3D11DeviceContext_Map(ctx, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &map), "Map");
    const unsigned char *p = map.pData;
    int r = p[0], g = p[1], b = p[2], a = p[3];
    ID3D11DeviceContext_Unmap(ctx, (ID3D11Resource *)staging, 0);

    int ok = within1(r, WANT_R) && within1(g, WANT_G) && within1(b, WANT_B) && within1(a, WANT_A);
    if (ok)
        printf("pixel ok\n");
    else
        printf("pixel BAD %d %d %d %d\n", r, g, b, a);
    printf("frame ms: %.4f\n", (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart / 100.0);

    IDXGIDevice *dxgi;
    IDXGIAdapter *adapter;
    DXGI_ADAPTER_DESC desc;
    char name[128];
    check(ID3D11Device_QueryInterface(dev, &IID_IDXGIDevice, (void **)&dxgi), "QueryInterface(IDXGIDevice)");
    check(IDXGIDevice_GetAdapter(dxgi, &adapter), "GetAdapter");
    check(IDXGIAdapter_GetDesc(adapter, &desc), "GetDesc");
    if (!WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, name, sizeof name, NULL, NULL))
        name[0] = 0;
    printf("adapter: %s\n", name);
    fflush(stdout);
    return ok ? 0 : 1;
}
