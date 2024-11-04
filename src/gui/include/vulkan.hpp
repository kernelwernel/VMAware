#include "imgui_impl_vulkan.h"
#include "imgui.h"
#include "imgui_impl_glfw.h"


namespace vulkan {
    bool IsExtensionAvailable(const ImVector<VkExtensionProperties>& properties, const char* extension);

    VkPhysicalDevice SetupVulkan_SelectPhysicalDevice(VkInstance &g_Instance);

    void SetupVulkan(ImVector<const char*> instance_extensions, VkInstance &g_Instance);

    void SetupVulkanWindow(ImGui_ImplVulkanH_Window* wd, VkSurfaceKHR surface, int width, int height);

    void CleanupVulkan();

    void CleanupVulkanWindow();

    void check_vk_result(VkResult err);
}