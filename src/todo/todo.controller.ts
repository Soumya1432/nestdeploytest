import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
} from '@nestjs/common';
import { TodoService } from './todo.service';
import { CreateTodoDto } from './dto/create-todo.dto';

@Controller('todo')
export class TodoController {
  constructor(private readonly todoService: TodoService) {}

  @Get()
  async fetchAllTodo() {
    const response = await this.todoService.fetchAllTodo();
    return response;
  }

  @Get(':id')
  async fetchTodoById(@Param('id') id: string) {
    const responseById = await this.todoService.fetchTodoById(id);
    return {
      responseById,
      message: 'Todo find successfully',
    };
  }

  @Post()
  async create(@Body() createTodoDto: CreateTodoDto) {
    const response = await this.todoService.createTodo(createTodoDto);

    return response.res;
  }

  @Patch(':id')
  async update(@Param('id') id: string, @Body() createTodoDto: CreateTodoDto) {
    const updateResponse = await this.todoService.updateTodo(createTodoDto, id);
    return updateResponse;
  }

  @Delete(':id')
  async deleteeData(@Param('id') id: string) {
    const deletedResponse = await this.todoService.deleteById(id);
    return deletedResponse;
  }
}
