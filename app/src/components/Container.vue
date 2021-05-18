<template>
  <div class="container">
    <el-container>
      <el-header>
        <el-row :gutter="40" style="height: 100%">
          <el-col
            :sm="4"
            :md="5"
            :lg="4"
            :xl="3"
            class="hidden-xs-only"
            style="height: 100%"
          >
            <el-image
              class="logo hidden-lg-and-up hidden-xs-only"
              :src="require('../assets/logo_alt.png')"
              :fit="'contain'"
            ></el-image>
            <el-image
              class="logo hidden-md-and-down"
              :src="require('../assets/logo.png')"
              :fit="'contain'"
            ></el-image>
          </el-col>
          <el-col :xs="20" :sm="16" :md="16" :lg="16" :xl="18">
            <el-menu
              class="navbar"
              :default-active="activeIndex"
              mode="horizontal"
              @select="handleSelect"
            >
              <el-menu-item index="1">文档</el-menu-item>
              <el-menu-item index="2">规则</el-menu-item>
              <el-menu-item index="3">关于</el-menu-item>
            </el-menu>
          </el-col>
          <el-col :xs="4" :sm="4" :md="3" :lg="4" :xl="3">
            <el-row style="height: 100%">
              <el-col v-if="!hasLogin" span="24" style="height: 100%">
                <el-button style="height: 100%; float: right" type="text"
                  >登录</el-button
                >
              </el-col>
              <el-col v-if="isAdmin && hasLogin" :span="12">
                <el-button style="height: 100%" type="text">管理</el-button>
              </el-col>
              <el-col v-if="hasLogin" :span="12">
                <el-button style="height: 100%" type="text">注销</el-button>
              </el-col>
            </el-row>
          </el-col>
        </el-row>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>
  </div>
</template>

<script>
import "@/style/template.css";
export default {
  name: "Container",
  props: {
    hasLogin: Boolean,
    isAdmin: Boolean,
  },
  data() {
    return {
      pageIndex: "1",
    };
  },
  methods: {
    handleSelect(key, keyPath) {
      console.log(key, keyPath);
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
.navbar {
  border-bottom: none !important;
}
.logo {
  height: 100%;
}
.container {
  height: 100vh;
}
.el-container {
  height: 100%;
}
</style>
