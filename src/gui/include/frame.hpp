#include "imgui.h"
#include "imgui_impl_vulkan.h"

namespace frame {
    void FrameRender(ImGui_ImplVulkanH_Window* wd, ImDrawData* draw_data);
    void FramePresent(ImGui_ImplVulkanH_Window* wd);
}