<template>
  <el-row style="height: 60px" type="flex" justify="center">
    <el-col>
      <header class="template-header">Not Found</header>
    </el-col>
  </el-row>
  <el-row style="height: calc(100% - 60px)" type="flex" justify="center">
    <el-col :sm="20" :md="20" :lg="20" :xl="20">
      <main class="template-main">
        <p style="font-size: 40px; letter-spacing: 8px; font-weight: 800">
          404
        </p>
        <p style="font-size: 30px">有些东西消失就回不来了。</p>
      </main>
    </el-col>
  </el-row>
</template>

<script>
export default {
  name: "notFound",
};
</script>

<style scoped>
</style>