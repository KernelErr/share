import { createRouter, createWebHistory } from 'vue-router'
import notFound from '@/views/code.vue'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: notFound //for test
  },
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router
