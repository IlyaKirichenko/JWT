using JWT.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWT.Controllers
{
    [Route("api/v1/tasks")]
    [ApiController]
    [Authorize]
    public class TaskController : ControllerBase
    {

        private readonly JwtContext _context;

        public TaskController(JwtContext context)
        {
            _context = context;
        }

        public record CreateTaskRequest(string Title, string Description);
        public record UpdateTaskRequest(string Title, string Description, bool IsCompleted);

        // GET: api/<TaskController>
        [HttpGet]
        public async Task<IActionResult> GetAllTasks()
        {
            var currentLogin = User.Identity?.Name;
            var task = await _context.Tasks.Where(o => o.OwnerLogin == currentLogin).ToListAsync();
            return Ok(task);
        }

        [HttpGet("all")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAllTaskAdmin()
        {
            var task = await _context.Tasks.ToListAsync();

            return Ok(task);
        }

        // GET api/<TaskController>/5
        [HttpGet("{id:int}")]
        public async Task<IActionResult> GetTask(int id)
        {
            var task = await _context.Tasks.FindAsync(id);

            if (task == null)
            {
                return NotFound();
            }

            if (!User.IsInRole("Admin") && User.Identity?.Name != task.OwnerLogin)
            {
                return Forbid(); //403
            }

            return Ok(task);
        }

        // POST api/<TaskController>
        [HttpPost]
        public async Task<IActionResult> PostTask([FromBody] CreateTaskRequest request)
        {
            var newTask = new Models.Task
            {
                Title = request.Title,
                Description = request.Description,
                OwnerLogin = User.Identity?.Name!,
                IsCompleted = false
            };

            _context.Tasks.Add(newTask);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetTask), new { id = newTask.Id }, newTask);
        }

        [HttpPut("{id:int}")]
        public async Task<IActionResult> PutTask(int id, [FromBody] UpdateTaskRequest newTask)
        {
            var exisTask = await _context.Tasks.FindAsync(id);

            if (exisTask == null)
            {
                return NotFound();
            }

            if (!User.IsInRole("Admin") && User.Identity?.Name != exisTask.OwnerLogin)
            {
                return Forbid(); //403
            }

            exisTask.Title = newTask.Title;
            exisTask.Description = newTask.Description;
            exisTask.IsCompleted = newTask.IsCompleted;

            await _context.SaveChangesAsync();

            return Ok(exisTask);
        }

        // DELETE api/<TaskController>/5
        [HttpDelete("{id:int}")]
        public async Task<IActionResult> DeleteTask(int id)
        {
            var task = await _context.Tasks.FindAsync(id);
            if(task == null)
            {
                return NotFound();
            }

            if (!User.IsInRole("Admin") && User.Identity?.Name != task.OwnerLogin)
            {
                return Forbid(); // 403
            }

            _context.Tasks.Remove(task);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}
